!function(e){function t(t){for(var i,o,s=t[0],l=t[1],d=t[2],u=0,m=[];u<s.length;u++)o=s[u],Object.prototype.hasOwnProperty.call(a,o)&&a[o]&&m.push(a[o][0]),a[o]=0;for(i in l)Object.prototype.hasOwnProperty.call(l,i)&&(e[i]=l[i]);for(c&&c(t);m.length;)m.shift()();return r.push.apply(r,d||[]),n()}function n(){for(var e,t=0;t<r.length;t++){for(var n=r[t],i=!0,s=1;s<n.length;s++){var l=n[s];0!==a[l]&&(i=!1)}i&&(r.splice(t--,1),e=o(o.s=n[0]))}return e}var i={},a={26:0},r=[];function o(t){if(i[t])return i[t].exports;var n=i[t]={i:t,l:!1,exports:{}};return e[t].call(n.exports,n,n.exports,o),n.l=!0,n.exports}o.e=function(e){var t=[],n=a[e];if(0!==n)if(n)t.push(n[2]);else{var i=new Promise((function(t,i){n=a[e]=[t,i]}));t.push(n[2]=i);var r,s=document.createElement("script");s.charset="utf-8",s.timeout=120,o.nc&&s.setAttribute("nonce",o.nc),s.src=function(e){return o.p+""+({}[e]||e)+".js"}(e);var l=new Error;r=function(t){s.onerror=s.onload=null,clearTimeout(d);var n=a[e];if(0!==n){if(n){var i=t&&("load"===t.type?"missing":t.type),r=t&&t.target&&t.target.src;l.message="Loading chunk "+e+" failed.\n("+i+": "+r+")",l.name="ChunkLoadError",l.type=i,l.request=r,n[1](l)}a[e]=void 0}};var d=setTimeout((function(){r({type:"timeout",target:s})}),12e4);s.onerror=s.onload=r,document.head.appendChild(s)}return Promise.all(t)},o.m=e,o.c=i,o.d=function(e,t,n){o.o(e,t)||Object.defineProperty(e,t,{enumerable:!0,get:n})},o.r=function(e){"undefined"!=typeof Symbol&&Symbol.toStringTag&&Object.defineProperty(e,Symbol.toStringTag,{value:"Module"}),Object.defineProperty(e,"__esModule",{value:!0})},o.t=function(e,t){if(1&t&&(e=o(e)),8&t)return e;if(4&t&&"object"==typeof e&&e&&e.__esModule)return e;var n=Object.create(null);if(o.r(n),Object.defineProperty(n,"default",{enumerable:!0,value:e}),2&t&&"string"!=typeof e)for(var i in e)o.d(n,i,function(t){return e[t]}.bind(null,i));return n},o.n=function(e){var t=e&&e.__esModule?function(){return e.default}:function(){return e};return o.d(t,"a",t),t},o.o=function(e,t){return Object.prototype.hasOwnProperty.call(e,t)},o.p="",o.oe=function(e){throw console.error(e),e};var s=window.webpackJsonp=window.webpackJsonp||[],l=s.push.bind(s);s.push=t,s=s.slice();for(var d=0;d<s.length;d++)t(s[d]);var c=l;r.push([2341,0]),n()}({2341:function(e,t,n){var i,a;n.p=function(){function e(e,t){if(window.$C&&window.$C.hasOwnProperty(e))return window.$C[e];if(void 0!==t)return t;throw new Error("getConfigValue - "+e+" not set, no default provided")}return function(){for(var t,n,i="",a=0,r=arguments.length;a<r;a++)(n=(t=arguments[a].toString()).length)>1&&"/"==t.charAt(n-1)&&(t=t.substring(0,n-1)),"/"!=t.charAt(0)?i+="/"+t:i+=t;if("/"!=i){var o=i.split("/"),s=o[1];if("static"==s||"modules"==s){var l=i.substring(s.length+2,i.length);i="/"+s,window.$C.BUILD_NUMBER&&(i+="/@"+window.$C.BUILD_NUMBER),window.$C.BUILD_PUSH_NUMBER&&(i+="."+window.$C.BUILD_PUSH_NUMBER),"app"==o[2]&&(i+=":"+e("APP_BUILD",0)),i+="/"+l}}var d=e("MRSPARKLE_ROOT_PATH","/"),c=e("LOCALE","en-US"),u="/"+c+i;return""==d||"/"==d?u:d+u}("/static/build/pages/enterprise")+"/"}(),i=[n("require/underscore"),n("routers/IndexesCloud"),n("models/indexes/cloud/Index"),n("util/router_utils")],void 0===(a=function(e,t,n,i){var a=function(e,n){new t({isSingleInstanceCloud:e,pageError:n});try{i.start_backbone_history()}catch(e){window.location="./"}};(new n).fetch().then((function(){a(!1,null)})).fail((function(e){404===e.status?a(!0,null):a(!0,e)}))}.apply(t,i))||(e.exports=a)},2342:function(e,t){e.exports='<td class="index-name">\n    <% if (model.entity.entry.links.get("edit")) { %>\n    <a href=<%- editLink %> class="editAction"><%- model.entity.entry.get("name") %></a>\n    <% } else { %>\n    <span class="disabled-action"><%- model.entity.entry.get("name") %></span>\n    <% } %>\n</td>\n<td class="actions">\n    <% if (model.entity.entry.links.get("edit")) { %>\n        <a href=<%- editLink %> class="editAction"><%= _("Edit").t() %></a>\n    <% } else { %>\n        <span class="disabled-action"><%= _("Edit").t() %></span>\n    <% } %>\n    <% if (isInternal) { %>\n        <span class="disabled-action"><%= _("Delete").t() %></span>\n    <% } else if (isRemoteIndex) { %>\n            <a href="#" class="disabled-action deleteAction"><%= _("Delete").t() %></a>\n    <% } else { %>\n        <% if (isEnabled) { %>\n            <a href="#" class="deleteAction"><%= _("Delete").t() %></a>\n        <% } else { %>\n            <span class="disabled-action"><%= _("Delete").t() %></span>\n        <% } %>\n    <% } %>\n</td>\n<td class="index-type">\n    <i class="icon-<%-model.entity.getDataType()%> icon-large"></i>\n    <%- formatDataType(model.entity.getDataType()) %>\n</td>\n<% if (user.canUseApps()) { %>\n<td class="index-app"><%- model.entity.entry.acl.get("app") %></td>\n<% } %>\n<td class="raw-size"><%- formatNumbersUtils.bytesToFileSize(rawSizeSingleInstance * 1024 * 1024) %></td> \x3c!-- format w/ size units --\x3e\n<td class="max-size">\n    <% if (isRemoteIndex) { %>\n        <% if (model.entity.entry.content.get("maxGlobalRawDataSizeMB") == "0") { %>\n            <%- _(\'unlimited\').t() %>\n        <% } else { %>\n            <%- formatNumbersUtils.bytesToFileSize(model.entity.entry.content.get("maxGlobalRawDataSizeMB") * 1024 * 1024) %> \x3c!-- format in GB --\x3e\n        <% } %>\n    <% } else { %>\n        <% if (model.entity.entry.content.get("maxTotalDataSizeMB") == "0") { %>\n            <%- _(\'unlimited\').t() %>\n        <% } else { %>\n            <%- formatNumbersUtils.bytesToFileSize(model.entity.entry.content.get("maxTotalDataSizeMB") * 1024 * 1024) %>\n        <% } %>\n    <% } %>\n</td> \x3c!-- format in GB --\x3e\n<td class="event-count" title="<%- splunkUtil.sprintf(_(\'%s events\').t(), model.entity.entry.content.get("totalEventCount")) %>"><%- formatNumbersUtils.abbreviateNumber(model.entity.entry.content.get("totalEventCount")) %></td> \x3c!-- Abbreviate number --\x3e\n<td class="earliest-event" title="<%- formatToLocalTime(model.entity.entry.content.get("minTime")) %>"><%- formatToRelativeTime(model.entity.entry.content.get("minTime")) %></td> \x3c!-- format into relative time --\x3e\n<td class="latest-event" title="<%- formatToLocalTime(model.entity.entry.content.get("maxTime")) %>"><%- formatToRelativeTime(model.entity.entry.content.get("maxTime")) %></td>\x3c!-- format into relative time --\x3e\n<td class="searchable-retention" title=\'<%- model.entity.entry.content.get("frozenTimePeriodInSecs") %>\'>\n    <% var frozenTimePeriodInSecs = model.entity.entry.content.get("frozenTimePeriodInSecs");\n       var frozenTimePeriodInSecsDisplay; %>\n    <% if (frozenTimePeriodInSecs == 0) { %>\n        <% frozenTimePeriodInSecsDisplay = _("keep indefinitely").t(); %>\n        <%- frozenTimePeriodInSecsDisplay %>\n    <% } else if (frozenTimePeriodInSecs > 0 && frozenTimePeriodInSecs < 86400) { %>\n        <% frozenTimePeriodInSecsDisplay = timeUtils.getRelativeStringFromSeconds(frozenTimePeriodInSecs, true) %>\n        <%- frozenTimePeriodInSecsDisplay %>\n    <% } else { %>\n        <% frozenTimePeriodInSecsDisplay = timeUtils.secondsToSeparatedDate(frozenTimePeriodInSecs, false); %>\n            <% if(frozenTimePeriodInSecsDisplay === \'keep indefinitely\') { %>\n                <%- frozenTimePeriodInSecsDisplay %>\n            <% } else { %>\n                <% if (frozenTimePeriodInSecsDisplay.years > 0) { %>\n                    <% if (frozenTimePeriodInSecsDisplay.years == 1) { %>\n                            <%- frozenTimePeriodInSecsDisplay.years %> <%= _(\'year\').t() %>   \n                    <% } else { %>\n                            <%- frozenTimePeriodInSecsDisplay.years %> <%= _(\'years\').t() %>\n                    <% } %>\n                <% } %>\n                <% if (frozenTimePeriodInSecsDisplay.days >= 1) { %>\n                    <% if (frozenTimePeriodInSecsDisplay.days == 1) { %>\n                        <%- frozenTimePeriodInSecsDisplay.days %> <%= _(\'day\').t() %>   \n                    <% } else { %>\n                        <%- frozenTimePeriodInSecsDisplay.days %> <%= _(\'days\').t() %>\n                    <% } %>\n                <% } %>\n            <% } %>\n    <% } %>\n</td> \x3c!-- format into relative time --\x3e\n\n<td class="index-status">\n    <div class="status-cell-placeholder"></div>\n</td>\n'},556:function(e,t){e.exports='<td class="index-name">\n    <% if (isEditableCloud) { %>\n    <a href=<%- editLink %> class="editAction"><%- model.entity.entry.get("name") %></a>\n    <% } else { %>\n    <span class="disabled-action"><%- model.entity.entry.get("name") %></span>\n    <% } %>\n</td>\n<td class="actions">\n    <% if (isEditableCloud) { %>\n    <a href=<%- editLink %> class="editAction"><%= _("Edit").t() %></a>\n    <% } else { %>\n    <span class="disabled-action"><%= _("Edit").t() %></span>\n    <% } %>\n    <% if (isInternal) { %>\n    <span class="disabled-action"><%= _("Delete").t() %></span>\n    <% } else { %>\n    <% if (isEnabled) { %>\n    <a href="#" class="deleteAction"><%= _("Delete").t() %></a>\n    <% } else { %>\n    <span class="disabled-action"><%= _("Delete").t() %></span>\n    <% } %>\n    <% } %>\n    <% if (archiverAppInstalled && hasArchive) { %>\n        <a href="#" class="retrieve-action"><%= _(\'Restore\').t() %></a>\n    <% } %>\n</td>\n<td class="index-type">\n    <i class="icon-<%-model.entity.getDataType()%> icon-large"></i>\n    <%- formatDataType(model.entity.getDataType()) %>\n</td>\n<% if (user.canUseApps()) { %>\n<td class="index-app"><%- model.entity.entry.content.get("eai:acl.appDisplayName") %></td>\n<% } %>\n<td class="raw-size">\n    <%- formatNumbersUtils.bytesToFileSize(model.entity.entry.content.get("totalRawSizeMB") * 1024 * 1024) %> \x3c!-- format w/ size units --\x3e\n</td>\n<% if (archiverAppInstalled || isRemoteIndex) { %>\n    <td class="max-size">\n        <% if (model.entity.entry.content.has("maxGlobalRawDataSizeMB")) { %>\n            <% if (model.entity.entry.content.get("maxGlobalRawDataSizeMB") == "0") { %>\n                <%- _(\'unlimited\').t() %>\n            <% } else { %>\n                <%- formatNumbersUtils.bytesToFileSize(model.entity.entry.content.get("maxGlobalRawDataSizeMB") * 1024 * 1024) %> \x3c!-- format in GB --\x3e\n            <% } %>\n            <% if (model.entity.entry.content.has("maxGlobalDataSizeMB") && model.entity.entry.content.get("maxGlobalDataSizeMB") !== "0") { %>\n                <% var maxGlobalDataSizeMB = formatNumbersUtils.bytesToFileSize(model.entity.entry.content.get("maxGlobalDataSizeMB") * 1024 * 1024) %>\n                <% var maxGlobalRawDataSizeMB = formatNumbersUtils.bytesToFileSize(model.entity.entry.content.get("maxGlobalRawDataSizeMB") * 1024 * 1024) %>\n                <span class="tooltip-link" rel="tooltip" data-title="<%- splunkUtil.sprintf(_(\'Conflicting settings! Disk usage is limited to %s. Raw data size is limited to %s. Splunk recommends you use the Edit action to ensure that only the raw data limit is applied.\').t(), maxGlobalDataSizeMB, maxGlobalRawDataSizeMB) %>" >\n                    <i class="icon-warning icon-large warnIcon"></i>\n                </span>\n            <% } %>\n        <% } else { %>\n            <% if (model.entity.entry.content.get("maxGlobalDataSizeMB") == "0") { %>\n                <%- _(\'unlimited\').t() %>\n            <% } else { %>\n                <%- formatNumbersUtils.bytesToFileSize(model.entity.entry.content.get("maxGlobalDataSizeMB") * 1024 * 1024) %> \x3c!-- format in GB --\x3e\n            <% } %>\n            <span class="tooltip-link" rel="tooltip" data-title="<%= _(\'The maximum size of this index is currently controlled based on disk usage. This is a legacy retention method and we strongly recommend that you reconfigure this limit to be based on raw data size instead, by using the Edit action.\').t() %>" >\n                <i class="icon-warning icon-large warnIcon"></i>\n            </span>\n        <% } %>\n    </td>\n<% } %>\n<td class="event-count" title="<%- splunkUtil.sprintf(_(\'%s events\').t(), model.entity.entry.content.get("totalEventCount")) %>"><%- formatNumbersUtils.abbreviateNumber(model.entity.entry.content.get("totalEventCount")) %></td> \x3c!-- Abbreviate number --\x3e\n<td class="earliest-event" title="<%- timeUtils.convertToLocalTime(model.entity.entry.content.get("minTime")) %>"><%- timeUtils.convertToRelativeTime(model.entity.entry.content.get("minTime")) %></td> \x3c!-- format into relative time --\x3e\n<td class="latest-event" title="<%- timeUtils.convertToLocalTime(model.entity.entry.content.get("maxTime")) %>"><%- timeUtils.convertToRelativeTime(model.entity.entry.content.get("maxTime")) %></td>\x3c!-- format into relative time --\x3e\n<td class="searchable-retention" title=\'<%- model.entity.entry.content.get("frozenTimePeriodInSecs") %>\'>\n    <% var frozenTimePeriodInSecs = model.entity.entry.content.get("frozenTimePeriodInSecs");\n       var frozenTimePeriodInSecsDisplay; %>\n    <% if (frozenTimePeriodInSecs == 0) { %>\n        <% frozenTimePeriodInSecsDisplay = _("keep indefinitely").t(); %>\n        <%- frozenTimePeriodInSecsDisplay %>\n    <% } else if (frozenTimePeriodInSecs > 0 && frozenTimePeriodInSecs < 86400) { %>\n        <% frozenTimePeriodInSecsDisplay = timeUtils.getRelativeStringFromSeconds(frozenTimePeriodInSecs, true) %>\n        <%- frozenTimePeriodInSecsDisplay %>\n    <% } else { %>\n        <% frozenTimePeriodInSecsDisplay = timeUtils.secondsToSeparatedDate(frozenTimePeriodInSecs, false); %>\n            <% if(frozenTimePeriodInSecsDisplay === \'keep indefinitely\') { %>\n                <%- frozenTimePeriodInSecsDisplay %>\n            <% } else { %>\n                <% if (frozenTimePeriodInSecsDisplay.years > 0) { %>\n                    <% if (frozenTimePeriodInSecsDisplay.years == 1) { %>\n                            <%- frozenTimePeriodInSecsDisplay.years %> <%= _(\'year\').t() %>\n                    <% } else { %>\n                            <%- frozenTimePeriodInSecsDisplay.years %> <%= _(\'years\').t() %>\n                    <% } %>\n                <% } %>\n                <% if (frozenTimePeriodInSecsDisplay.days >= 1) { %>\n                    <% if (frozenTimePeriodInSecsDisplay.days == 1) { %>\n                        <%- frozenTimePeriodInSecsDisplay.days %> <%= _(\'day\').t() %>\n                    <% } else { %>\n                        <%- frozenTimePeriodInSecsDisplay.days %> <%= _(\'days\').t() %>\n                    <% } %>\n                <% } %>\n            <% } %>\n    <% } %> </td> \x3c!-- format into relative time --\x3e\n\n<% if (archiverAppInstalled) { %>\n    <td class="archive-retention" title=\'<%- _("Archive Retention").t() %>\'>\n      <% if (model.entity.entry.content.get("archiver.coldStorageProvider")) { %>\n        <a target="_blank" rel="noopener noreferrer" href=<%- archiveMgmtLink %>>\n            <%- formatArchiveRetention(model.entity.entry.content.get("archiver.coldStorageRetentionPeriod"))%>\n        </a>\n      <% } %>\n    </td>\n    <td class="self-storage" title=\'<%- _("Self Storage").t() %>\'>\n        <% if (model.entity.entry.content.get("archiver.selfStorageProvider")) { %>\n            <a target="_blank" rel="noopener noreferrer" href=<%- bucketLocationLink %>>\n                <%- archiveBucketExists %>\n            </a>\n        <% } %>\n    </td>\n<% } %>\n\n<td class="index-status">\n    <div class="status-cell-placeholder"></div>\n</td>\n'},"collections/indexes/cloud/Indexes":function(e,t,n){var i,a;i=[n("require/underscore"),n("models/indexes/cloud/Index"),n("collections/services/data/Indexes"),n("shim/splunk.util")],void 0===(a=function(e,t,n,i){return n.extend({model:t,url:"cluster_blaster_indexes/sh_indexes_manager",initialize:function(){n.prototype.initialize.apply(this,arguments)}})}.apply(t,i))||(e.exports=a)},"models/indexes/cloud/Archiver":function(e,t,n){"use strict";n(1),Object.defineProperty(t,"__esModule",{value:!0});var i=s(n(10)),a=s(n("models/SplunkDBase")),r=n("models/indexes/cloud/CloudIndexValidation"),o=s(n("require/underscore"));function s(e){return e&&e.__esModule?e:{default:e}}t.default=a.default.extend({url:"cluster_blaster_indexes/sh_indexes_manager",urlRoot:"cluster_blaster_indexes/sh_indexes_manager",defaults:{name:"",datatype:"event",maxIndexSizeFormat:"GB","archiver.coldStorageRetentionPeriod":"",frozenTimePeriodInDays:""},getColdStorageProvider:function(){return"Glacier"},validation:(0,i.default)({},r.validationObj,{"archiver.coldStorageRetentionPeriod":[{fn:function(e,t,n){return"Glacier"!==n["archiver.coldStorageProvider"]||e?"":(0,o.default)("Archive Retention Period is required.").t()}}]})}),e.exports=t.default},"models/indexes/cloud/CloudIndex":function(e,t,n){"use strict";n(1),Object.defineProperty(t,"__esModule",{value:!0});var i,a=n("models/services/data/Indexes"),r=(i=a)&&i.__esModule?i:{default:i},o=n("models/indexes/cloud/CloudIndexValidation");t.default=r.default.extend({validation:o.validationObj}),e.exports=t.default},"models/indexes/cloud/DynamicDataArchiveConfig":function(e,t,n){"use strict";(function(i){n(1),Object.defineProperty(t,"__esModule",{value:!0});var a=m(n(10)),r=m(n(11)),o=m(n(13)),s=n(34),l=n(26),d=m(n(35)),c=n(150),u=n(7);function m(e){return e&&e.__esModule?e:{default:e}}var f=function(){function e(){(0,r.default)(this,e),this.enablerUrl="data_archive/sh_archive_manager",this.isEnabled=!1,this.maxRetentionPeriod=0,this.error={hasError:!1,message:""},this.isEnabled=!1,this.maxRetentionPeriod=0}return(0,o.default)(e,[{key:"fetchEnabler",value:function(){return i((0,l.createRESTURL)(this.enablerUrl+"?"+d.default.encode({output_mode:"json"})),(0,a.default)({},s.defaultFetchInit,{method:"GET"})).then((0,s.handleResponse)(200)).catch((0,s.handleError)((0,u._)("Unable to fetch archive enabler.")))}},{key:"parseConfigSettings",value:function(e){e&&e.entry[0]&&e.entry[0].content&&(this.isEnabled=(0,c.normalizeBoolean)(e.entry[0].content["archiver.enableDataArchive"]),this.maxRetentionPeriod=Number(e.entry[0].content["archiver.maxDataArchiveRetentionPeriod"]),this.error.hasError=!1,this.error.message="")}},{key:"getConfigSettings",value:function(){var e=this;return this.fetchEnabler().then((function(t){return e.parseConfigSettings(t)})).catch((function(t){e.isEnabled=!1,e.maxRetentionPeriod=0,e.error.hasError=!0,e.error.message=t.message}))}}]),e}();t.default=f,e.exports=t.default}).call(this,n(31))},"models/indexes/shared/IndexFetchData":function(e,t,n){var i,a;i=[n("require/underscore"),n("models/shared/EAIFilterFetchData"),n("util/splunkd_utils")],void 0===(a=function(e,t,n){return t.extend({getCalculatedSearch:function(){var i=t.prototype.getCalculatedSearch.apply(this,arguments),a=this.get("nameFilter");return e.isUndefined(a)||e.isEmpty(a)||(i+=" AND "+n.createSearchFilterString(a,["name"],{})),""==i?i="isVirtual=0":""!=i&&(i+=" AND isVirtual=0"),i}})}.apply(t,i))||(e.exports=a)},"models/indexes/shared/NoInternalIndexFetchData":function(e,t,n){var i,a;i=[n("require/underscore"),n("models/shared/EAIFilterFetchData"),n("util/splunkd_utils")],void 0===(a=function(e,t,n){return t.extend({getCalculatedSearch:function(){var i=t.prototype.getCalculatedSearch.apply(this,arguments),a=this.get("nameFilter");return e.isUndefined(a)||e.isEmpty(a)||(i+=" AND "+n.createSearchFilterString(a,["name"],{})),""==i?i="isVirtual=0":""!=i&&(i+=" AND isVirtual=0"),i+=" AND isInternal=0"}})}.apply(t,i))||(e.exports=a)},"models/services/data/Archiver":function(e,t,n){"use strict";n(1),Object.defineProperty(t,"__esModule",{value:!0});var i,a=n("models/SplunkDBase"),r=(i=a)&&i.__esModule?i:{default:i},o=n("models/indexes/cloud/CloudIndexValidation");t.default=r.default.extend({url:"data/archiver",urlRoot:"data/archiver",defaults:{name:"",maxIndexSize:"",maxIndexSizeFormat:"GB",frozenTimePeriodInDays:"","archive.enabled":!1,"archive.provider":"",datatype:"event"},validation:o.validationObj}),e.exports=t.default},"routers/IndexesCloud":function(e,t,n){var i,a;i=[n("require/underscore"),n("require/backbone"),n("routers/IndexesBase"),n("models/indexes/cloud/Archiver"),n("models/indexes/cloud/DynamicDataArchiveConfig"),n("models/services/data/Archiver"),n("models/indexes/cloud/Index"),n("models/indexes/cloud/CloudIndex"),n("collections/indexes/cloud/Indexes"),n("collections/services/data/Indexes"),n("collections/indexes/cloud/Archives"),n("models/indexes/shared/IndexFetchData"),n("models/indexes/shared/NoInternalIndexFetchData"),n("views/error/Master"),n("views/indexes/cloud/AddEditIndexDialog"),n("views/indexes/shared/PageController"),n(556),n(2342)],void 0===(a=function(e,t,n,i,a,r,o,s,l,d,c,u,m,f,p,y,h,g){return n.extend({initialize:function(t){n.prototype.initialize.apply(this,arguments),this.setPageTitle(e("Manage Indexes").t()),this.isSingleInstanceCloud=!!e.isObject(t)&&!!t.isSingleInstanceCloud,this.pageError=t.pageError},createController:function(n,v){if(!this.model.user.canEditIndexes()||this.pageError){var x=e("Access Denied").t(),S=e("You do not have permission to view this page.").t();this.pageError&&(x=this.pageError.status+" - "+this.pageError.statusText,S=this.pageError.responseJSON.messages&&this.pageError.responseJSON.messages.length?this.pageError.responseJSON.messages[0].text:this.pageError.statusText);var b=new f({model:{application:this.model.application,error:new t.Model({status:x,message:S})}});return b.model.controller=new t.Model,b}var I=this.collection.appLocals.isArchiverAppInstalled()?r:s;return new y({model:n||this.model,router:this,isCloud:!0,isSingleInstanceCloud:this.isSingleInstanceCloud,collection:v||this.collection,archivesCollectionClass:c,dynamicDataArchiveConfig:new a,archiverModelClass:this.isSingleInstanceCloud?I:i,indexModelClass:this.isSingleInstanceCloud?s:o,indexesCollectionClass:this.isSingleInstanceCloud?d:l,indexesFetchDataClass:this.isSingleInstanceCloud?m:u,addEditDialogClass:p,showAppFilter:!1,showConfirmSaveDialog:!this.isSingleInstanceCloud,showConfirmDeleteDialog:!this.isSingleInstanceCloud,templates:{gridRow:this.isSingleInstanceCloud?g:h}})}})}.apply(t,i))||(e.exports=a)}});