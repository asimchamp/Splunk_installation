!function(e){function t(t){for(var r,o,s=t[0],i=t[1],u=t[2],c=0,f=[];c<s.length;c++)o=s[c],Object.prototype.hasOwnProperty.call(n,o)&&n[o]&&f.push(n[o][0]),n[o]=0;for(r in i)Object.prototype.hasOwnProperty.call(i,r)&&(e[r]=i[r]);for(d&&d(t);f.length;)f.shift()();return l.push.apply(l,u||[]),a()}function a(){for(var e,t=0;t<l.length;t++){for(var a=l[t],r=!0,s=1;s<a.length;s++){var i=a[s];0!==n[i]&&(r=!1)}r&&(l.splice(t--,1),e=o(o.s=a[0]))}return e}var r={},n={10:0},l=[];function o(t){if(r[t])return r[t].exports;var a=r[t]={i:t,l:!1,exports:{}};return e[t].call(a.exports,a,a.exports,o),a.l=!0,a.exports}o.e=function(e){var t=[],a=n[e];if(0!==a)if(a)t.push(a[2]);else{var r=new Promise((function(t,r){a=n[e]=[t,r]}));t.push(a[2]=r);var l,s=document.createElement("script");s.charset="utf-8",s.timeout=120,o.nc&&s.setAttribute("nonce",o.nc),s.src=function(e){return o.p+""+({}[e]||e)+".js"}(e);var i=new Error;l=function(t){s.onerror=s.onload=null,clearTimeout(u);var a=n[e];if(0!==a){if(a){var r=t&&("load"===t.type?"missing":t.type),l=t&&t.target&&t.target.src;i.message="Loading chunk "+e+" failed.\n("+r+": "+l+")",i.name="ChunkLoadError",i.type=r,i.request=l,a[1](i)}n[e]=void 0}};var u=setTimeout((function(){l({type:"timeout",target:s})}),12e4);s.onerror=s.onload=l,document.head.appendChild(s)}return Promise.all(t)},o.m=e,o.c=r,o.d=function(e,t,a){o.o(e,t)||Object.defineProperty(e,t,{enumerable:!0,get:a})},o.r=function(e){"undefined"!=typeof Symbol&&Symbol.toStringTag&&Object.defineProperty(e,Symbol.toStringTag,{value:"Module"}),Object.defineProperty(e,"__esModule",{value:!0})},o.t=function(e,t){if(1&t&&(e=o(e)),8&t)return e;if(4&t&&"object"==typeof e&&e&&e.__esModule)return e;var a=Object.create(null);if(o.r(a),Object.defineProperty(a,"default",{enumerable:!0,value:e}),2&t&&"string"!=typeof e)for(var r in e)o.d(a,r,function(t){return e[t]}.bind(null,r));return a},o.n=function(e){var t=e&&e.__esModule?function(){return e.default}:function(){return e};return o.d(t,"a",t),t},o.o=function(e,t){return Object.prototype.hasOwnProperty.call(e,t)},o.p="",o.oe=function(e){throw console.error(e),e};var s=window.webpackJsonp=window.webpackJsonp||[],i=s.push.bind(s);s.push=t,s=s.slice();for(var u=0;u<s.length;u++)t(s[u]);var d=i;l.push([1630,0]),a()}({1630:function(e,t,a){a.p=function(){function e(e,t){if(window.$C&&window.$C.hasOwnProperty(e))return window.$C[e];if(void 0!==t)return t;throw new Error("getConfigValue - "+e+" not set, no default provided")}return function(){for(var t,a,r="",n=0,l=arguments.length;n<l;n++)(a=(t=arguments[n].toString()).length)>1&&"/"==t.charAt(a-1)&&(t=t.substring(0,a-1)),"/"!=t.charAt(0)?r+="/"+t:r+=t;if("/"!=r){var o=r.split("/"),s=o[1];if("static"==s||"modules"==s){var i=r.substring(s.length+2,r.length);r="/"+s,window.$C.BUILD_NUMBER&&(r+="/@"+window.$C.BUILD_NUMBER),window.$C.BUILD_PUSH_NUMBER&&(r+="."+window.$C.BUILD_PUSH_NUMBER),"app"==o[2]&&(r+=":"+e("APP_BUILD",0)),r+="/"+i}}var u=e("MRSPARKLE_ROOT_PATH","/"),d=e("LOCALE","en-US"),c="/"+d+r;return""==u||"/"==u?c:u+c}("/static/build/pages/lite")+"/"}(),a(1);var r=l(a("routers/ArchiveManagement")),n=l(a("util/router_utils"));function l(e){return e&&e.__esModule?e:{default:e}}new r.default,n.default.start_backbone_history()},"routers/ArchiveManagement":function(e,t,a){"use strict";(function(r){a(1),Object.defineProperty(t,"__esModule",{value:!0});var n=v(a(10)),l=v(a("require/underscore")),o=v(a("shim/jquery")),s=v(a(0)),i=v(a("util/react_render")),u=v(a("views/shared/react/Error")),d=v(a("routers/Base")),c=v(a(35)),f=a(26),m=a(34),h=v(a("uri/route")),p=v(a("views/archive_management/ArchiveManagement"));function v(e){return e&&e.__esModule?e:{default:e}}var y=d.default.extend({initialize:function(){for(var e,t=arguments.length,a=Array(t),r=0;r<t;r++)a[r]=arguments[r];(e=d.default.prototype.initialize).call.apply(e,[this].concat(a)),this.setPageTitle((0,l.default)("Archive Management").t()),this.enableAppBar=!1,this.fetchAppLocals=!0,this.fetchServerInfo=!0},fetchRestoreHistory:function(e){return r((0,f.createRESTURL)("restore_history_sh"),(0,n.default)({},m.defaultFetchInit,{method:"POST",body:c.default.encode(e)})).then((0,m.handleResponse)(200)).catch((0,m.handleError)((0,l.default)("Unable to process restore history.").t()))},fetchArchiveMetadata:function(e){return r((0,f.createRESTURL)("index_restore_sh"),(0,n.default)({},m.defaultFetchInit,{method:"POST",body:c.default.encode(e)})).then((0,m.handleResponse)(200)).catch((0,m.handleError)((0,l.default)("Unable to fetch archive metadata.").t()))},page:function(){for(var e,t=this,a=arguments.length,r=Array(a),n=0;n<a;n++)r[n]=arguments[n];(e=d.default.prototype.page).call.apply(e,[this].concat(r));var c={learnMoreLink:h.default.docHelp(this.model.application.get("root"),this.model.application.get("locale"),"learnmore.dynamic_data_active_archive"),onFetchHistory:this.fetchRestoreHistory,onFetchArchive:this.fetchArchiveMetadata};o.default.when(this.deferreds.pageViewRendered,this.deferreds.appLocals,this.deferreds.serverInfo).done((function(){if((0,o.default)(".preload").replaceWith(t.pageView.el),t.collection.appLocals.isArchiverAppInstalled())(0,i.default)(s.default.createElement(p.default,c),t.pageView.$(".main-section-body").get(0));else{var e={model:{application:t.model.application,serverInfo:t.model.serverInfo},message:(0,l.default)("You do not have permission to view the contents of this page. Contact Splunk support to learn more.").t()};(0,i.default)(s.default.createElement(u.default,e),t.pageView.$(".main-section-body").get(0))}}))}});t.default=y,e.exports=t.default}).call(this,a(31))},"views/archive_management/ArchiveManagement":function(e,t,a){"use strict";a(1),Object.defineProperty(t,"__esModule",{value:!0});var r=h(a(11)),n=h(a(13)),l=h(a(15)),o=h(a(16)),s=a(0),i=h(s),u=h(a(2)),d=a(7),c=h(a(305)),f=h(a("views/archive_management/panels/Restore")),m=h(a("views/archive_management/panels/Archive"));function h(e){return e&&e.__esModule?e:{default:e}}var p=function(e){function t(e,a){(0,r.default)(this,t);var n=(0,l.default)(this,(t.__proto__||Object.getPrototypeOf(t)).call(this,e,a));return n.handleChange=function(e,t){n.setState({activePanelId:t.activePanelId})},n.state={activePanelId:"archive"},n}return(0,o.default)(t,e),(0,n.default)(t,[{key:"render",value:function(){return i.default.createElement("div",null,i.default.createElement(c.default,{activePanelId:this.state.activePanelId,onChange:this.handleChange},i.default.createElement(c.default.Panel,{label:(0,d._)("Archive"),panelId:"archive",style:{margin:20}},i.default.createElement(m.default,{learnMoreLink:this.props.learnMoreLink,onFetchArchive:this.props.onFetchArchive})),i.default.createElement(c.default.Panel,{label:(0,d._)("Restore"),panelId:"restore",style:{margin:20}},i.default.createElement(f.default,{learnMoreLink:this.props.learnMoreLink,onFetchHistory:this.props.onFetchHistory}))))}}]),t}(s.Component);p.propTypes={learnMoreLink:u.default.string.isRequired,onFetchHistory:u.default.func.isRequired,onFetchArchive:u.default.func.isRequired},t.default=p,e.exports=t.default},"views/archive_management/panels/Archive":function(e,t,a){"use strict";a(1),Object.defineProperty(t,"__esModule",{value:!0});var r=w(a(11)),n=w(a(13)),l=w(a(15)),o=w(a(16)),s=(0,w(a(55)).default)(["\n    color: ","\n"],["\n    color: ","\n"]),i=a(0),u=w(i),d=w(a(2)),c=w(a(9)),f=w(a(136)),m=w(a(46)),h=w(a(38)),p=w(a(47)),v=w(a(22)),y=w(a(29)),_=a(7),g=a(19),E=a("views/shared/indexes/cloud/DynamicDataArchiveUtils");function w(e){return e&&e.__esModule?e:{default:e}}var b=[{sortKey:"IndexName",label:(0,_._)("Index Name")},{sortKey:"raw_size",label:(0,_._)("Current Size (GB)"),tooltipMsg:(0,_._)("The current amount of raw data (uncompressed) that is stored in the archive for each index. ")},{sortKey:"earliest",label:(0,_._)("Earliest Event")},{sortKey:"latest",label:(0,_._)("Latest Event")},{sortKey:"90-day-archived",label:(0,_._)("90-Day Data Growth (GB)"),tooltipMsg:(0,_._)("The amount of raw data (uncompressed) that has been added to the archive in the past 90 days for each index.")},{sortKey:"90-day-expired",label:(0,_._)("90-Day Data Expiration (GB)"),tooltipMsg:(0,_._)("The amount of raw data (uncompressed) that has aged out of the archive within the past 90-day window for each index.")}],x=c.default.span(s,(function(e){return e.isError&&(0,g.pick)({enterprise:{light:g.variables.errorColorD20,dark:g.variables.errorColorL10}})})),T=function(e){function t(){var e;(0,r.default)(this,t);for(var a=arguments.length,n=Array(a),o=0;o<a;o++)n[o]=arguments[o];var s=(0,l.default)(this,(e=t.__proto__||Object.getPrototypeOf(t)).call.apply(e,[this].concat(n)));return s.componentDidMount=function(){var e=(0,E.constructHistoryData)();e.action="time_ranges",s.props.onFetchArchive(e).then((function(e){"success"===e.status&&s.setState({items:e.time_ranges,quarterlyArchiveGrowth:(0,E.convertToGB)(e.quarterlyArchiveGrowth),quarterlyExpiryGrowth:(0,E.convertToGB)(e.quarterlyExpiryGrowth),loading:!1})})).catch((function(){s.setState({loading:!1})})),e={action:"total_archive_usage",start_time:0,end_time:0,output_mode:"json"},s.props.onFetchArchive(e).then((function(e){s.setState({totalUsage:(0,E.convertToGB)(e.raw_size),entitlement:e.entitlement})}))},s.state={items:[],loading:!0},s}return(0,o.default)(t,e),(0,n.default)(t,[{key:"render",value:function(){var e=["IndexName","raw_size","earliest","latest","90-day-archived","90-day-expired"],t=!!(this.state.totalUsage-this.state.entitlement>0);return u.default.createElement("div",null,u.default.createElement(h.default,{level:1,"data-test-name":"archive-summary-heading"},(0,_._)("Archive Summary")),u.default.createElement(y.default,null,(0,_._)("This page provides an overview of archived data usage for indexes enabled with the Dynamic Data Active Archive feature."),u.default.createElement(v.default,{to:this.props.learnMoreLink,openInNewContext:!0,"data-test-name":"archive-summary-learnMoreLink",style:{marginLeft:"5px"}},(0,_._)("Learn More"))),u.default.createElement(f.default,{"data-test-name":"archive-summary-list",termWidth:300},u.default.createElement(f.default.Term,{"data-test-name":"total-archive-term"},(0,_._)("Total Archive Usage")),u.default.createElement(f.default.Description,{"data-test-name":"total-archive-desc"},u.default.createElement(x,{isError:t},this.state.totalUsage+" GB "),t&&u.default.createElement(u.default.Fragment,null,u.default.createElement(m.default,{"data-test-name":"total-archive-tooltip",content:(0,_._)("Your total archive usage exceeds your total entitlement")}))),u.default.createElement(f.default.Term,{"data-test-name":"total-entitlement-term"},(0,_._)("Total Entitlement")),u.default.createElement(f.default.Description,{"data-test-name":"total-entitlement-desc"},this.state.entitlement>0?this.state.entitlement+" GB":"N/A"),u.default.createElement(f.default.Term,{"data-test-name":"monthly-growth-term"},(0,_._)("Total Archive Data Growth (90 Days)"),u.default.createElement(m.default,{"data-test-name":"archive-growth-tooltip",style:{marginLeft:"5px"},content:(0,_._)("The total amount of raw data (uncompressed) that has been added to the archive in the past 90 days.")})),u.default.createElement(f.default.Description,{"data-test-name":"quarterly-growth-desc"},this.state.quarterlyArchiveGrowth+" GB"),u.default.createElement(f.default.Term,{"data-test-name":"quarterly-expiry-term"},(0,_._)("Total Archive Data Expiration (90 Days) "),u.default.createElement(m.default,{"data-test-name":"archive-expiration-tooltip",style:{marginLeft:"5px"},content:(0,_._)("The total amount of raw data (uncompressed) that has aged out of the archive within the past 90-day window. ")})),u.default.createElement(f.default.Description,{"data-test-name":"monthly-expiry-desc"},this.state.quarterlyExpiryGrowth+" GB")),this.state.loading&&u.default.createElement("div",{"data-test":"loading-msg",style:{marginTop:"100px",textAlign:"center"}},(0,_._)("Loading...")),0===this.state.items.length&&!1===this.state.loading&&E.emptyArchiveTemplate,this.state.items.length>0&&!1===this.state.loading&&u.default.createElement("div",{style:{marginTop:"20px"}},u.default.createElement(p.default,{stripeRows:!0},u.default.createElement(p.default.Head,null,b.map((function(e){return u.default.createElement(p.default.HeadCell,{"data-test":e.sortKey,key:e.sortKey},e.label,e.tooltipMsg&&u.default.createElement(m.default,{"data-test":"archive-table-"+e.label+"-tooltip",content:e.tooltipMsg,style:{marginLeft:"5px"}}))}))),u.default.createElement(p.default.Body,null,this.state.items.map((function(t,a){var r="row-"+a;return u.default.createElement(p.default.Row,{key:r,"data-test":r},e.map((function(e){return u.default.createElement(p.default.Cell,{key:e,"data-test":r+"-"+e},(0,E.getFormattedValue)(e,t[e]))})))}))))))}}]),t}(i.Component);T.propTypes={learnMoreLink:d.default.string.isRequired,onFetchArchive:d.default.func.isRequired},t.default=T,e.exports=t.default},"views/archive_management/panels/Restore":function(e,t,a){"use strict";a(1),Object.defineProperty(t,"__esModule",{value:!0});var r=_(a(10)),n=_(a(11)),l=_(a(13)),o=_(a(15)),s=_(a(16)),i=a(0),u=_(i),d=_(a(2)),c=_(a(47)),f=_(a(136)),m=_(a(38)),h=a(7),p=a("util/test_support"),v=function(e){if(e&&e.__esModule)return e;var t={};if(null!=e)for(var a in e)Object.prototype.hasOwnProperty.call(e,a)&&(t[a]=e[a]);return t.default=e,t}(a("views/shared/indexes/cloud/DynamicDataArchiveUtils")),y=_(a("views/archive_management/panels/RestoreSummary"));function _(e){return e&&e.__esModule?e:{default:e}}var g=function(e){function t(e,a){(0,n.default)(this,t);var r=(0,o.default)(this,(t.__proto__||Object.getPrototypeOf(t)).call(this,e,a));return r.componentDidMount=function(){r.props.onFetchHistory(v.constructHistoryData()).then((function(e){r.setState({items:e.items,summary:e.summary,totalSizeRestored:e.total_size_restored,totalSizeExpired:e.total_size_expired,totalSizeFlushed:e.total_size_flushed})}))},r.getExpansion=function(e){return u.default.createElement(c.default.Row,{key:e.RequestId+"-expansion","data-test":e.RequestId+"-expanded-row"},u.default.createElement(c.default.Cell,{style:{borderTop:"none"},colSpan:7},u.default.createElement(f.default,null,["RequestId","EmailAddresses"].map((function(t){return u.default.createElement("div",{key:e[t]},u.default.createElement(f.default.Term,null,v.localisedStrings[t]),u.default.createElement(f.default.Description,{style:{whiteSpace:"pre-wrap"}},e[t]||" "))})),u.default.createElement("div",{key:"reason"},u.default.createElement(f.default.Term,null,(0,h._)("Reason")),u.default.createElement(f.default.Description,null,v.getAdditionalStateInfo(e.State))))))},r.handleSort=function(e,t){var a=t.sortKey,n=v.getNextSortDir(r.state.sortKey,r.state.sortDir,a);r.setState({sortKey:a,sortDir:n}),r.props.onFetchHistory(v.constructHistoryData("",a,n)).then((function(e){e.count>0&&r.setState({items:e.items})}))},r.state={sortKey:"IndexName",sortDir:"asc",items:[],requestId:""},r}return(0,s.default)(t,e),(0,l.default)(t,[{key:"render",value:function(){var e=this,t=this.state,a=t.sortKey,n=t.sortDir,l=v.getRestoreHistoryColumns(this.state.items);return u.default.createElement("div",null,u.default.createElement(y.default,{"data-test":"restore-summary-table",summary:this.state.summary,totalRestored:this.state.totalSizeRestored,totalExpired:this.state.totalSizeExpired,totalFlushed:this.state.totalSizeFlushed}),this.state.items.length>0?u.default.createElement("div",null,u.default.createElement(m.default,{"data-test-name":"restore-history-heading"},(0,h._)("Last 50 Restore Request History")),u.default.createElement(c.default,(0,r.default)({rowExpansion:"single",stripeRows:!0,headType:"fixed",innerStyle:{maxHeight:800}},(0,p.createTestHook)(null,"ArchiveRestoreHistoryTable")),u.default.createElement(c.default.Head,null,l.map((function(t){return u.default.createElement(c.default.HeadCell,{key:t.sortKey,onSort:"Description"!==t.sortKey?e.handleSort:void 0,sortKey:t.sortKey,sortDir:t.sortKey===a?n:"none"},t.label)})),u.default.createElement(c.default.HeadCell,{key:"TimeToExpire"},(0,h._)("Expiration Date"))),u.default.createElement(c.default.Body,null,this.state.items.map((function(t,a){var r="row-"+a;return u.default.createElement(c.default.Row,{key:r,"data-test":r,expansionRow:e.getExpansion(t)},v.headers.map((function(e){return u.default.createElement(c.default.Cell,{key:e,"data-test":r+"-"+e},"State"===e&&v.getStateIcon(t[e]),v.getFormattedValue(e,t[e]))})),u.default.createElement(c.default.Cell,{key:"TimeToExpire","data-test":r+"-TimeToExpire"},"Failed"!==t.State.substring(0,6)&&v.getExpirationDate(t.RequestTime)))}))))):v.emptyTemplate)}}]),t}(i.Component);g.propTypes={onFetchHistory:d.default.func.isRequired},t.default=g,e.exports=t.default},"views/archive_management/panels/RestoreSummary":function(e,t,a){"use strict";a(1),Object.defineProperty(t,"__esModule",{value:!0});var r=m(a(0)),n=m(a(2)),l=m(a(47)),o=m(a(38)),s=m(a(136)),i=m(a(46)),u=m(a(22)),d=m(a(29)),c=a(7),f=a("views/shared/indexes/cloud/DynamicDataArchiveUtils");function m(e){return e&&e.__esModule?e:{default:e}}var h=function(e){var t=[{sortKey:"index_name",label:(0,c._)("Index Name")},{sortKey:"count",label:(0,c._)("Restore Request Count"),tooltipMsg:(0,c._)("The total number of restoration requests, including both successful and failed restore requests. This value also includes cleared and expired restore requests. ")},{sortKey:"size_restored",label:(0,c._)("Restore Size (GB)"),tooltipMsg:(0,c._)("The total amount of raw data (uncompressed) that has been restored. ")},{sortKey:"count_flushed",label:(0,c._)("Cleared Count"),tooltipMsg:(0,c._)("The total number of restored index requests that have been manually deleted.")},{sortKey:"size_flushed",label:(0,c._)("Cleared Size (GB)"),tooltipMsg:(0,c._)("The total amount of raw data (uncompressed) that has been manually deleted.")},{sortKey:"count_expired",label:(0,c._)("Expired Count"),tooltipMsg:(0,c._)("The total number of restored index requests that have aged out.")},{sortKey:"size_expired",label:(0,c._)("Expired Size (GB)"),tooltipMsg:(0,c._)("The total amount of restored raw data (uncompressed) that has aged out.")}],a=["index_name","count","size_restored","count_flushed","size_flushed","count_expired","size_expired"];return r.default.createElement("div",null,r.default.createElement(o.default,{level:1,"data-test-name":"restore-summary-heading"},(0,c._)("Restore Activity Summary (90 days)")),r.default.createElement(d.default,null,(0,c._)("Overview of restoration activity for indexes enabled with Dynamic Data Active Archive."),r.default.createElement(u.default,{to:e.learnMoreLink,openInNewContext:!0,"data-test-name":"archive-summary-learnMoreLink",style:{marginLeft:"5px"}},(0,c._)("Learn More"))),r.default.createElement(s.default,{termWidth:300,"data-test-name":"restore-summary-list"},r.default.createElement(s.default.Term,{"data-test-name":"total-restore-term"},(0,c._)("Total Restored Data (GB)"),r.default.createElement(i.default,{"data-test-name":"total-restore-term-tooltip",style:{marginLeft:"5px"},content:(0,c._)("The total amount of raw data (uncompressed) that has been restored.")})),r.default.createElement(s.default.Description,{"data-test-name":"total-restore-desc"},e.totalRestored+" GB"),r.default.createElement(s.default.Term,{"data-test-name":"total-flush-term"},(0,c._)("Total Cleared Data (GB)"),r.default.createElement(i.default,{"data-test-name":"total-flush-term-tooltip",style:{marginLeft:"5px"},content:(0,c._)("The total amount of raw data  (uncompressed) that has been deleted from the restored archive.")})),r.default.createElement(s.default.Description,{"data-test-name":"total-flush-desc"},e.totalFlushed+" GB"),r.default.createElement(s.default.Term,{"data-test-name":"total-expired-term"},(0,c._)("Total Expired Data (GB)"),r.default.createElement(i.default,{"data-test-name":"total-expired-term-tooltip",style:{marginLeft:"5px"},content:(0,c._)("The total amount of raw data (uncompressed) that has aged out from the restored archived.")})),r.default.createElement(s.default.Description,{"data-test-name":"total-expired-desc"},e.totalExpired+" GB")),e.summary&&e.summary.length&&r.default.createElement("div",{style:{marginTop:"20px"}},r.default.createElement(l.default,{stripeRows:!0,"data-test-name":"restore-summary-table"},r.default.createElement(l.default.Head,null,t.map((function(e){return r.default.createElement(l.default.HeadCell,{"data-test":e.sortKey,key:e.sortKey},e.label)}))),r.default.createElement(l.default.Body,null,e.summary.map((function(e,t){var n="row-"+t;return r.default.createElement(l.default.Row,null,a.map((function(t){return r.default.createElement(l.default.Cell,{key:t,"data-test":n+"-"+t},(0,f.getFormattedValue)(t,e[t]))})))}))))))};h.propTypes={summary:n.default.arrayOf(n.default.shape({index_name:n.default.string,count:n.default.number,size_restored:n.default.number,size_flushed:n.default.number,size_expired:n.default.number,last_restored:n.default.number})).isRequired,totalRestored:n.default.number.isRequired,totalExpired:n.default.number.isRequired,totalFlushed:n.default.number.isRequired,learnMoreLink:n.default.string.isRequired},t.default=h,e.exports=t.default},"views/shared/react/Error":function(e,t,a){"use strict";a(1),Object.defineProperty(t,"__esModule",{value:!0});var r=f(a(11)),n=f(a(13)),l=f(a(15)),o=f(a(16)),s=f(a(2)),i=f(a("components/BackboneAdapterBase")),u=a(7),d=f(a("views/error/Master")),c=f(a("require/backbone"));function f(e){return e&&e.__esModule?e:{default:e}}var m=function(e){function t(){return(0,r.default)(this,t),(0,l.default)(this,(t.__proto__||Object.getPrototypeOf(t)).apply(this,arguments))}return(0,o.default)(t,e),(0,n.default)(t,[{key:"getView",value:function(){return new d.default({model:{application:this.props.model.application,serverInfo:this.props.serverInfo,error:new c.default.Model({status:this.props.status,message:this.props.message})}})}}]),t}(i.default);m.propTypes={model:s.default.shape({application:s.default.shape({}),serverInfo:s.default.shape({})}),status:s.default.string,message:s.default.string},m.defaultProps={model:{application:new c.default.Model({content:new c.default.Model}),serverInfo:new c.default.Model({content:new c.default.Model})},status:(0,u._)("404 Not Found"),message:(0,u._)("Page not found!")},t.default=m,e.exports=t.default}});