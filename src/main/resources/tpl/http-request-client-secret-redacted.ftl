<#ftl output_format="HTML">
<#-- @ftlvariable name="data" type="io.qameta.allure.attachment.http.HttpRequestAttachment" -->
<#--
  Copy of the default allure-rest-assured request template (tpl/http-request.ftl, allure 2.29.1)
  that redacts the client secret in form parameters, body and curl.
-->
<#assign redactedParams = ["client_secret"]>
<#assign redactedValue = "[ REDACTED ]">
<#function redact text>
    <#local result = text>
    <#list redactedParams as param>
        <#local result = result?replace("(" + param + "=)[^&' ]*", "$1" + redactedValue, "r")>
    </#list>
    <#return result>
</#function>
<div><#if data.method??>${data.method}<#else>GET</#if> to <#if data.url??>${redact(data.url)}<#else>Unknown</#if></div>

<#if data.body??>
    <h4>Body</h4>
    <div>
    <pre class="preformated-text">
    <#t>${redact(data.body)}
    </pre>
    </div>
</#if>

<#if (data.headers)?has_content>
    <h4>Headers</h4>
    <div>
        <#list data.headers as name, value>
            <div>${name}: ${value!"null"}</div>
        </#list>
    </div>
</#if>


<#if (data.cookies)?has_content>
    <h4>Cookies</h4>
    <div>
        <#list data.cookies as name, value>
            <div>${name}: ${value!"null"}</div>
        </#list>
    </div>
</#if>

<#if data.curl??>
    <h4>Curl</h4>
    <div>
        ${redact(data.curl)}
    </div>
</#if>

<#if (data.formParams)?has_content>
    <h4>FormParams</h4>
    <div>
        <#list data.formParams as name, value>
            <div>${name}: <#if redactedParams?seq_contains(name)>${redactedValue}<#else>${value!"null"}</#if></div>
        </#list>
    </div>
</#if>
