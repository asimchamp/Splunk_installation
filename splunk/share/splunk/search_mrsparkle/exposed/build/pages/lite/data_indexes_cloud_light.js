!function(e){function t(t){for(var i,o,s=t[0],l=t[1],d=t[2],m=0,u=[];m<s.length;m++)o=s[m],Object.prototype.hasOwnProperty.call(r,o)&&r[o]&&u.push(r[o][0]),r[o]=0;for(i in l)Object.prototype.hasOwnProperty.call(l,i)&&(e[i]=l[i]);for(c&&c(t);u.length;)u.shift()();return a.push.apply(a,d||[]),n()}function n(){for(var e,t=0;t<a.length;t++){for(var n=a[t],i=!0,s=1;s<n.length;s++){var l=n[s];0!==r[l]&&(i=!1)}i&&(a.splice(t--,1),e=o(o.s=n[0]))}return e}var i={},r={27:0},a=[];function o(t){if(i[t])return i[t].exports;var n=i[t]={i:t,l:!1,exports:{}};return e[t].call(n.exports,n,n.exports,o),n.l=!0,n.exports}o.e=function(e){var t=[],n=r[e];if(0!==n)if(n)t.push(n[2]);else{var i=new Promise((function(t,i){n=r[e]=[t,i]}));t.push(n[2]=i);var a,s=document.createElement("script");s.charset="utf-8",s.timeout=120,o.nc&&s.setAttribute("nonce",o.nc),s.src=function(e){return o.p+""+({}[e]||e)+".js"}(e);var l=new Error;a=function(t){s.onerror=s.onload=null,clearTimeout(d);var n=r[e];if(0!==n){if(n){var i=t&&("load"===t.type?"missing":t.type),a=t&&t.target&&t.target.src;l.message="Loading chunk "+e+" failed.\n("+i+": "+a+")",l.name="ChunkLoadError",l.type=i,l.request=a,n[1](l)}r[e]=void 0}};var d=setTimeout((function(){a({type:"timeout",target:s})}),12e4);s.onerror=s.onload=a,document.head.appendChild(s)}return Promise.all(t)},o.m=e,o.c=i,o.d=function(e,t,n){o.o(e,t)||Object.defineProperty(e,t,{enumerable:!0,get:n})},o.r=function(e){"undefined"!=typeof Symbol&&Symbol.toStringTag&&Object.defineProperty(e,Symbol.toStringTag,{value:"Module"}),Object.defineProperty(e,"__esModule",{value:!0})},o.t=function(e,t){if(1&t&&(e=o(e)),8&t)return e;if(4&t&&"object"==typeof e&&e&&e.__esModule)return e;var n=Object.create(null);if(o.r(n),Object.defineProperty(n,"default",{enumerable:!0,value:e}),2&t&&"string"!=typeof e)for(var i in e)o.d(n,i,function(t){return e[t]}.bind(null,i));return n},o.n=function(e){var t=e&&e.__esModule?function(){return e.default}:function(){return e};return o.d(t,"a",t),t},o.o=function(e,t){return Object.prototype.hasOwnProperty.call(e,t)},o.p="",o.oe=function(e){throw console.error(e),e};var s=window.webpackJsonp=window.webpackJsonp||[],l=s.push.bind(s);s.push=t,s=s.slice();for(var d=0;d<s.length;d++)t(s[d]);var c=l;a.push([2343,0]),n()}({2343:function(e,t,n){var i,r;n.p=function(){function e(e,t){if(window.$C&&window.$C.hasOwnProperty(e))return window.$C[e];if(void 0!==t)return t;throw new Error("getConfigValue - "+e+" not set, no default provided")}return function(){for(var t,n,i="",r=0,a=arguments.length;r<a;r++)(n=(t=arguments[r].toString()).length)>1&&"/"==t.charAt(n-1)&&(t=t.substring(0,n-1)),"/"!=t.charAt(0)?i+="/"+t:i+=t;if("/"!=i){var o=i.split("/"),s=o[1];if("static"==s||"modules"==s){var l=i.substring(s.length+2,i.length);i="/"+s,window.$C.BUILD_NUMBER&&(i+="/@"+window.$C.BUILD_NUMBER),window.$C.BUILD_PUSH_NUMBER&&(i+="."+window.$C.BUILD_PUSH_NUMBER),"app"==o[2]&&(i+=":"+e("APP_BUILD",0)),i+="/"+l}}var d=e("MRSPARKLE_ROOT_PATH","/"),c=e("LOCALE","en-US"),m="/"+c+i;return""==d||"/"==d?m:d+m}("/static/build/pages/lite")+"/"}(),i=[n("routers/IndexesCloudLight"),n("util/router_utils")],void 0===(r=function(e,t){new e;try{t.start_backbone_history()}catch(e){window.location="./"}}.apply(t,i))||(e.exports=r)},556:function(e,t){e.exports='<td class="index-name">\n    <% if (isEditableCloud) { %>\n    <a href=<%- editLink %> class="editAction"><%- model.entity.entry.get("name") %></a>\n    <% } else { %>\n    <span class="disabled-action"><%- model.entity.entry.get("name") %></span>\n    <% } %>\n</td>\n<td class="actions">\n    <% if (isEditableCloud) { %>\n    <a href=<%- editLink %> class="editAction"><%= _("Edit").t() %></a>\n    <% } else { %>\n    <span class="disabled-action"><%= _("Edit").t() %></span>\n    <% } %>\n    <% if (isInternal) { %>\n    <span class="disabled-action"><%= _("Delete").t() %></span>\n    <% } else { %>\n    <% if (isEnabled) { %>\n    <a href="#" class="deleteAction"><%= _("Delete").t() %></a>\n    <% } else { %>\n    <span class="disabled-action"><%= _("Delete").t() %></span>\n    <% } %>\n    <% } %>\n    <% if (archiverAppInstalled && hasArchive) { %>\n        <a href="#" class="retrieve-action"><%= _(\'Restore\').t() %></a>\n    <% } %>\n</td>\n<td class="index-type">\n    <i class="icon-<%-model.entity.getDataType()%> icon-large"></i>\n    <%- formatDataType(model.entity.getDataType()) %>\n</td>\n<% if (user.canUseApps()) { %>\n<td class="index-app"><%- model.entity.entry.content.get("eai:acl.appDisplayName") %></td>\n<% } %>\n<td class="raw-size">\n    <%- formatNumbersUtils.bytesToFileSize(model.entity.entry.content.get("totalRawSizeMB") * 1024 * 1024) %> \x3c!-- format w/ size units --\x3e\n</td>\n<% if (archiverAppInstalled || isRemoteIndex) { %>\n    <td class="max-size">\n        <% if (model.entity.entry.content.has("maxGlobalRawDataSizeMB")) { %>\n            <% if (model.entity.entry.content.get("maxGlobalRawDataSizeMB") == "0") { %>\n                <%- _(\'unlimited\').t() %>\n            <% } else { %>\n                <%- formatNumbersUtils.bytesToFileSize(model.entity.entry.content.get("maxGlobalRawDataSizeMB") * 1024 * 1024) %> \x3c!-- format in GB --\x3e\n            <% } %>\n            <% if (model.entity.entry.content.has("maxGlobalDataSizeMB") && model.entity.entry.content.get("maxGlobalDataSizeMB") !== "0") { %>\n                <% var maxGlobalDataSizeMB = formatNumbersUtils.bytesToFileSize(model.entity.entry.content.get("maxGlobalDataSizeMB") * 1024 * 1024) %>\n                <% var maxGlobalRawDataSizeMB = formatNumbersUtils.bytesToFileSize(model.entity.entry.content.get("maxGlobalRawDataSizeMB") * 1024 * 1024) %>\n                <span class="tooltip-link" rel="tooltip" data-title="<%- splunkUtil.sprintf(_(\'Conflicting settings! Disk usage is limited to %s. Raw data size is limited to %s. Splunk recommends you use the Edit action to ensure that only the raw data limit is applied.\').t(), maxGlobalDataSizeMB, maxGlobalRawDataSizeMB) %>" >\n                    <i class="icon-warning icon-large warnIcon"></i>\n                </span>\n            <% } %>\n        <% } else { %>\n            <% if (model.entity.entry.content.get("maxGlobalDataSizeMB") == "0") { %>\n                <%- _(\'unlimited\').t() %>\n            <% } else { %>\n                <%- formatNumbersUtils.bytesToFileSize(model.entity.entry.content.get("maxGlobalDataSizeMB") * 1024 * 1024) %> \x3c!-- format in GB --\x3e\n            <% } %>\n            <span class="tooltip-link" rel="tooltip" data-title="<%= _(\'The maximum size of this index is currently controlled based on disk usage. This is a legacy retention method and we strongly recommend that you reconfigure this limit to be based on raw data size instead, by using the Edit action.\').t() %>" >\n                <i class="icon-warning icon-large warnIcon"></i>\n            </span>\n        <% } %>\n    </td>\n<% } %>\n<td class="event-count" title="<%- splunkUtil.sprintf(_(\'%s events\').t(), model.entity.entry.content.get("totalEventCount")) %>"><%- formatNumbersUtils.abbreviateNumber(model.entity.entry.content.get("totalEventCount")) %></td> \x3c!-- Abbreviate number --\x3e\n<td class="earliest-event" title="<%- timeUtils.convertToLocalTime(model.entity.entry.content.get("minTime")) %>"><%- timeUtils.convertToRelativeTime(model.entity.entry.content.get("minTime")) %></td> \x3c!-- format into relative time --\x3e\n<td class="latest-event" title="<%- timeUtils.convertToLocalTime(model.entity.entry.content.get("maxTime")) %>"><%- timeUtils.convertToRelativeTime(model.entity.entry.content.get("maxTime")) %></td>\x3c!-- format into relative time --\x3e\n<td class="searchable-retention" title=\'<%- model.entity.entry.content.get("frozenTimePeriodInSecs") %>\'>\n    <% var frozenTimePeriodInSecs = model.entity.entry.content.get("frozenTimePeriodInSecs");\n       var frozenTimePeriodInSecsDisplay; %>\n    <% if (frozenTimePeriodInSecs == 0) { %>\n        <% frozenTimePeriodInSecsDisplay = _("keep indefinitely").t(); %>\n        <%- frozenTimePeriodInSecsDisplay %>\n    <% } else if (frozenTimePeriodInSecs > 0 && frozenTimePeriodInSecs < 86400) { %>\n        <% frozenTimePeriodInSecsDisplay = timeUtils.getRelativeStringFromSeconds(frozenTimePeriodInSecs, true) %>\n        <%- frozenTimePeriodInSecsDisplay %>\n    <% } else { %>\n        <% frozenTimePeriodInSecsDisplay = timeUtils.secondsToSeparatedDate(frozenTimePeriodInSecs, false); %>\n            <% if(frozenTimePeriodInSecsDisplay === \'keep indefinitely\') { %>\n                <%- frozenTimePeriodInSecsDisplay %>\n            <% } else { %>\n                <% if (frozenTimePeriodInSecsDisplay.years > 0) { %>\n                    <% if (frozenTimePeriodInSecsDisplay.years == 1) { %>\n                            <%- frozenTimePeriodInSecsDisplay.years %> <%= _(\'year\').t() %>\n                    <% } else { %>\n                            <%- frozenTimePeriodInSecsDisplay.years %> <%= _(\'years\').t() %>\n                    <% } %>\n                <% } %>\n                <% if (frozenTimePeriodInSecsDisplay.days >= 1) { %>\n                    <% if (frozenTimePeriodInSecsDisplay.days == 1) { %>\n                        <%- frozenTimePeriodInSecsDisplay.days %> <%= _(\'day\').t() %>\n                    <% } else { %>\n                        <%- frozenTimePeriodInSecsDisplay.days %> <%= _(\'days\').t() %>\n                    <% } %>\n                <% } %>\n            <% } %>\n    <% } %> </td> \x3c!-- format into relative time --\x3e\n\n<% if (archiverAppInstalled) { %>\n    <td class="archive-retention" title=\'<%- _("Archive Retention").t() %>\'>\n      <% if (model.entity.entry.content.get("archiver.coldStorageProvider")) { %>\n        <a target="_blank" rel="noopener noreferrer" href=<%- archiveMgmtLink %>>\n            <%- formatArchiveRetention(model.entity.entry.content.get("archiver.coldStorageRetentionPeriod"))%>\n        </a>\n      <% } %>\n    </td>\n    <td class="self-storage" title=\'<%- _("Self Storage").t() %>\'>\n        <% if (model.entity.entry.content.get("archiver.selfStorageProvider")) { %>\n            <a target="_blank" rel="noopener noreferrer" href=<%- bucketLocationLink %>>\n                <%- archiveBucketExists %>\n            </a>\n        <% } %>\n    </td>\n<% } %>\n\n<td class="index-status">\n    <div class="status-cell-placeholder"></div>\n</td>\n'},"models/indexes/shared/NoInternalIndexFetchData":function(e,t,n){var i,r;i=[n("require/underscore"),n("models/shared/EAIFilterFetchData"),n("util/splunkd_utils")],void 0===(r=function(e,t,n){return t.extend({getCalculatedSearch:function(){var i=t.prototype.getCalculatedSearch.apply(this,arguments),r=this.get("nameFilter");return e.isUndefined(r)||e.isEmpty(r)||(i+=" AND "+n.createSearchFilterString(r,["name"],{})),""==i?i="isVirtual=0":""!=i&&(i+=" AND isVirtual=0"),i+=" AND isInternal=0"}})}.apply(t,i))||(e.exports=r)},"routers/IndexesCloudLight":function(e,t,n){var i,r;i=[n("require/underscore"),n("routers/IndexesBase"),n("models/services/data/Indexes"),n("collections/services/data/Indexes"),n("models/indexes/shared/NoInternalIndexFetchData"),n("views/indexes/cloud/AddEditIndexDialog"),n("views/indexes/shared/PageController"),n(556)],void 0===(r=function(e,t,n,i,r,a,o,s){return t.extend({createController:function(e,t){return new o({model:e||this.model,router:this,isCloud:!0,isCloudLight:!0,indexModelClass:n,collection:t||this.collection,archivesCollectionClass:void 0,indexesCollectionClass:i,indexesFetchDataClass:r,addEditDialogClass:a,templates:{gridRow:s}})}})}.apply(t,i))||(e.exports=r)}});