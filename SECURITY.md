# CAT 告警页 /r/alert 未授权写入并原样渲染告警内容导致存储型 XSS

**产出时间**：2026-11-11 18:26:53

## 漏洞描述

CAT（Central Application Tracking）4.0-RC1 的告警页存在存储型 XSS。`/r/alert?op=insert` 把请求参数 `content`、`metric`、`domain`、`category` 原样写入 `alert` 表（`report/page/alert/Handler.java:135`），`/r/alert?op=view` 展示时在 `jsp/report/alert/alertView.jsp:93` 用 `${alert.content}`、在 `:76`/`:82` 用 `${alertDomain.name}` 直接输出，未做任何 HTML 转义。由于 `/r/*` 的访问控制在默认部署下恒返回默认角色 1，写入与展示都不需要登录。

## 互联网资产证明

> 用于在公开资产测绘平台定位同类应用资产；优先使用应用自身稳定特征，不把漏洞路径、PoC 参数或一次性业务数据当作唯一指纹。测绘语句不允许出现「或」关系。

### 精准测绘语法

#### FOFA

```text
title="cat with sso" && body="payload"
```

#### X 情报社区

```text
title="cat with sso" && body="payload"
```

## 漏洞技术细节

### 1. 写入口：`/r/alert?op=insert`（Handler.java:128-147）

```java
	case INSERT:
		if (StringUtils.isEmpty(payload.getDomain())) {
			setAlertResult(model, 4);
		} else {
			Alert alertEntity = buildAlertEntity(payload);   // content/metric/category 原样取自请求
			try {
				int count = m_alertDao.insert(alertEntity);  // 落库，无任何过滤/转义
```

`buildAlertEntity`（`src/cat-home/src/main/java/com/dianping/cat/report/page/alert/Handler.java:62-72`）逐字段 set：`content=payload.getContent()`、`metric=payload.getMetric()`、`domain=payload.getDomain()`、`category=payload.getCategory()`。`Payload`（同目录 `Payload.java`）只用 `@FieldMeta` 做参数绑定，`getContent()`/`getDomain()` 仅判空，没有任何字符清洗。

同一根因的内部写点（不经 HTTP 也能落脏数据）：

```java
// src/cat-alarm/src/main/java/com/dianping/cat/alarm/service/AlertService.java:62-74
	private Alert buildAlert(AlertEntity alertEntity, SendMessageEntity message) {
		Alert alert = new Alert();
		...
		alert.setContent(message.getTitle() + "<br/>" + message.getContent());
```

由 `AlertManager.send`（`src/cat-alarm/src/main/java/com/dianping/cat/alarm/spi/AlertManager.java:192-193`）调用 `m_alertService.insert(alert, message)` 写入。

### 2. 渲染点：`/r/alert?op=view` → `alertView.jsp`

```jsp
<%-- src/cat-home/src/main/webapp/jsp/report/alert/alertView.jsp:93 --%>
<td><span class="text-primary">${alert.metric}</span><br/>${alert.content}</td>
<%-- :76 / :82 --%>
${w:shorten(alertDomain.name, 30)}
<h4 class="text-danger text-center">项目：${alertDomain.name}&nbsp;...</h4>
```

JSP EL `${...}` 不做 HTML 转义（本应用 `web.xml` 未配置任何 `<jsp-property-group>`/`<el-ignored>`，全库也无 `c:out`/`fn:escapeXml` 包裹这些字段），`alert.content` 列类型是 `longtext`（`src/script/CatApplication.sql:194-205`），长度不受 200 字符限制。

视图选择链：`Handler.handleOutbound` 的 `VIEW` 分支设 `model.setAction(VIEW)` → `JspViewer.getJspFilePath` 返回 `JspFile.VIEW.getPath()` = `/jsp/report/alert/alertView.jsp`。

### 3. 为什么无需登录（默认部署）

`web.xml` 中 `/r/*`、`/s/*` 只挂 `cat-filter`（链路追踪）、`permission-filter`、`domain-filter`（写 `CAT_DOMAINS` cookie），唯一的访问控制点是 `permission-filter`。

`PermissionFilter.doFilter`（`src/cat-home/src/main/java/com/dianping/cat/system/page/permission/PermissionFilter.java:91-94`）：

```java
			int resourceRole = m_resourceConfigManager.getRole(requestURI, op);

			if (resourceRole == ResourceConfigManager.DEFAULT_RESOURCE_ROLE) {
				chain.doFilter(request, response);   // 直接放行
```

`ResourceConfigManager.getRole`（`ResourceConfigManager.java:68-88`）以 `m_permissions.get(path)` 取键，`path` 是 `request.getRequestURI()` 的完整值（部署在 `/cat` 下即 `/cat/r/alert`）；而出厂 `src/cat-home/src/main/resources/config/resource-config.xml` 只有 3 条短键记录且没有 `*` 兜底项：

```xml
<resource-config>
  <resource path="/r" op="view" role="2"/>
  <resource path="/r" op="test" role="1"/>
  <resource path="/s/config" op="view" role="2"/>
</resource-config>
```

一级查找与 `m_permissions.get("*")` 二级回落全部 miss，恒返回 `DEFAULT_RESOURCE_ROLE = 1`，filter 走第一个分支直接放行。`report/page/alert/Handler` 也没有 `@PreInboundActionMeta("login")`（全库仅 `system/page/config/Handler.java:80,88` 与 `system/page/business/Handler.java:76,84` 有）。

### 4. 会话 cookie 无 HttpOnly

`CookieManager.createCookie`（`src/cat-home/src/main/java/com/dianping/cat/system/page/login/service/CookieManager.java`）：

```java
	protected Cookie createCookie(String name, String value) {
		Cookie cookie = new Cookie(name, value);

		cookie.setPath("/");
		return cookie;
	}
```

未设置 `HttpOnly`/`Secure`/`SameSite`，令牌名固定为 `ct`（`Token.TOKEN`），因此页面中的脚本可直接 `document.cookie` 读取并外发。

## 复现步骤

1. 匿名写入：

```
POST /cat/r/alert?op=insert HTTP/1.1
Host: cat.example.com
Content-Type: application/x-www-form-urlencoded

op=insert&domain=cat&category=zabbix&type=call&level=warning&metric=catxss1&alertTime=2024-05-01+10%3A00&content=%3Cimg+src%3Dx+onerror%3Dalert(document.domain)%3Ecatxss1
```

2. 任意用户（含管理员）打开列表：

```
GET /cat/r/alert?op=view&domain=cat&startTime=2024-05-01+09%3A50&endTime=2024-05-01+10%3A10&count=10&alertType= HTTP/1.1
Host: cat.example.com
```

响应正文中 payload 未转义出现在告警内容单元格，脚本在 CAT 源执行。

3. 脚本读取 `ct` cookie 并外发，即以该被窃会话身份发起后续请求（`CookieManager` 未设 `HttpOnly`，脚本可直接读到令牌）。

## PoC

```
python3 poc.py -u http://127.0.0.1:8080/cat
python3 poc.py -u http://127.0.0.1:8080/cat --proxy http://127.0.0.1:8888 --zh
```

脚本先 `op=insert` 写入带唯一标记的 payload，再 `op=view` 取回列表，检查响应中 payload 是否原样未转义出现；带 `--proxy` 时所有请求（含 127.0.0.1）强制走代理。

## 危害

- 任意匿名访问者可向 `alert` 表注入任意 HTML/JS；告警列表是运维与值班人员日常查看的页面，注入内容无过期清理，长期驻留。
- 页面无 CSP，脚本在 CAT 源执行后可读取 `ct` 会话 cookie（无 HttpOnly），据此以被窃会话身份操作后台，形成持久化利用；也可伪造页面内表单提交。
- `/r/storage` 的告警面板通过 `AlertService.query` 复用同一批数据，触发面进一步扩大。

## 局部验证

本项目为局部验证（不搭 Docker 靶场）。本轮尝试以 Java harness 复刻默认配置下的鉴权判定与渲染（`ResourceConfigManager.getRole` + `refreshData`、`PermissionFilter.doFilter` 分支、`Handler.buildAlertEntity`、`alertView.jsp` EL 输出）并加载出厂 `resource-config.xml`，但沙箱镜像 `vulnhunter/sandbox:latest` 缺失（RunCode 返回 `failure_class=image_missing`），harness 未能在沙箱内执行，故本条证据级别为 `static_only`。

静态结论已可完整闭合链路：出厂配置无 `*` 兜底且键为短路径 → `getRole` 恒返 1 → `PermissionFilter` 第一节分支 `chain.doFilter` → `Handler` 的 `INSERT` 分支把 `content`/`domain`/`metric` 原样交 `m_alertDao.insert` → `alertView.jsp` 三处 `${...}` 原样输出。harness 源码见 `vulns/234/Harness.java`（未执行）。

## 修复建议

1. `alertView.jsp` 中所有告警字段改用 `<c:out value="${...}"/>` 或 `fn:escapeXml()` 输出，`w:shorten` 的结果同样需要转义。
2. 写入侧对 `content` 做白名单 HTML 净化（现网仅需 `<br/>`、`<a href>` 等少量标签），`Handler.buildAlertEntity` 与 `AlertService.buildAlert` 统一处理。
3. 修正 `ResourceConfigManager.getRole`：按 context 相对路径或前缀匹配，并启用 `*` 兜底角色；给 `/r/alert` 等写操作补 `@PreInboundActionMeta("login")`。
4. `CookieManager.createCookie` 增加 `HttpOnly`、`Secure`、`SameSite=Lax`。

## 同根因受影响点

- `src/cat-alarm/src/main/java/com/dianping/cat/alarm/service/AlertService.java:65`（`buildAlert` 拼接 title+content 原样入库）
- `src/cat-alarm/src/main/java/com/dianping/cat/alarm/spi/AlertManager.java:192-193`（`message.setContent(dbContent)` 后 `m_alertService.insert`）
- `src/cat-home/src/main/webapp/jsp/report/alert/alertView.jsp:76,82,93`（未转义输出点）

---

## 审核标注

- 攻击面：前台
- 配置前提：默认配置
- 严重度：中危（medium）
- CVSS 3.1：6.1
- 评分向量：CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N
- CVSS 4.0：5.3
- CVSS 4.0 向量：CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:P/VC:L/VI:L/VA:N/SC:N/SI:N/SA:N
- 价值分层：有 CVE 价值（cve_candidate）
- 分层理由：默认部署下 /r/* 的 ResourceConfigManager.getRole 用完整 requestURI 查短键且无 * 兜底，恒返回默认角色 1，PermissionFilter 直接放行，Handler 无登录注解，匿名即可 op=insert 落库任意 HTML；alertView.jsp 三处 ${...} 原样输出，构成前端未授权写入的存储型 XSS。危害按 XSS 常规口径为会话令牌窃取与页面篡改，故 C/I 标 L 而非 H。本轮沙箱镜像缺失，证据为 static_only。
- 根因合并键：stored_xss:report.page.alert.alertView
