!function(e){function t(t){for(var n,a,s=t[0],c=t[1],l=t[2],f=0,d=[];f<s.length;f++)a=s[f],Object.prototype.hasOwnProperty.call(o,a)&&o[a]&&d.push(o[a][0]),o[a]=0;for(n in c)Object.prototype.hasOwnProperty.call(c,n)&&(e[n]=c[n]);for(u&&u(t);d.length;)d.shift()();return i.push.apply(i,l||[]),r()}function r(){for(var e,t=0;t<i.length;t++){for(var r=i[t],n=!0,s=1;s<r.length;s++){var c=r[s];0!==o[c]&&(n=!1)}n&&(i.splice(t--,1),e=a(a.s=r[0]))}return e}var n={},o={8:0},i=[];function a(t){if(n[t])return n[t].exports;var r=n[t]={i:t,l:!1,exports:{}};return e[t].call(r.exports,r,r.exports,a),r.l=!0,r.exports}a.e=function(){return Promise.resolve()},a.m=e,a.c=n,a.d=function(e,t,r){a.o(e,t)||Object.defineProperty(e,t,{enumerable:!0,get:r})},a.r=function(e){"undefined"!=typeof Symbol&&Symbol.toStringTag&&Object.defineProperty(e,Symbol.toStringTag,{value:"Module"}),Object.defineProperty(e,"__esModule",{value:!0})},a.t=function(e,t){if(1&t&&(e=a(e)),8&t)return e;if(4&t&&"object"==typeof e&&e&&e.__esModule)return e;var r=Object.create(null);if(a.r(r),Object.defineProperty(r,"default",{enumerable:!0,value:e}),2&t&&"string"!=typeof e)for(var n in e)a.d(r,n,function(t){return e[t]}.bind(null,n));return r},a.n=function(e){var t=e&&e.__esModule?function(){return e.default}:function(){return e};return a.d(t,"a",t),t},a.o=function(e,t){return Object.prototype.hasOwnProperty.call(e,t)},a.p="";var s=window.webpackJsonp=window.webpackJsonp||[],c=s.push.bind(s);s.push=t,s=s.slice();for(var l=0;l<s.length;l++)t(s[l]);var u=c;i.push([1626,0]),r()}({1626:function(e,t,r){r.p=function(){function e(e,t){if(window.$C&&window.$C.hasOwnProperty(e))return window.$C[e];if(void 0!==t)return t;throw new Error("getConfigValue - "+e+" not set, no default provided")}return function(){for(var t,r,n="",o=0,i=arguments.length;o<i;o++)(r=(t=arguments[o].toString()).length)>1&&"/"==t.charAt(r-1)&&(t=t.substring(0,r-1)),"/"!=t.charAt(0)?n+="/"+t:n+=t;if("/"!=n){var a=n.split("/"),s=a[1];if("static"==s||"modules"==s){var c=n.substring(s.length+2,n.length);n="/"+s,window.$C.BUILD_NUMBER&&(n+="/@"+window.$C.BUILD_NUMBER),window.$C.BUILD_PUSH_NUMBER&&(n+="."+window.$C.BUILD_PUSH_NUMBER),"app"==a[2]&&(n+=":"+e("APP_BUILD",0)),n+="/"+c}}var l=e("MRSPARKLE_ROOT_PATH","/"),u=e("LOCALE","en-US"),f="/"+u+n;return""==l||"/"==l?f:l+f}("/static/build/pages/enterprise")+"/"}(),r(1);var n,o=r(0),i=(n=o)&&n.__esModule?n:{default:n},a=u(r(40)),s=u(r(9)),c=r(485),l=r(7);function u(e){if(e&&e.__esModule)return e;var t={};if(null!=e)for(var r in e)Object.prototype.hasOwnProperty.call(e,r)&&(t[r]=e[r]);return t.default=e,t}var f={react:i.default,"react-dom":a,"styled-components":s},d={id:"uploaded_apps",name:"Uploaded Apps",version:"1.latest",localRoot:"build/pages/enterprise/remoteApps"},p={pageTitle:(0,l._)(d.name)};(0,c.loadShellApp)({remoteConfig:d,singletonLibs:f,layoutOptions:p})},485:function(e,t,r){(function(t){
/*!
 * Copyright © 2018 Splunk Inc.
 * SPLUNK CONFIDENTIAL – Use or disclosure of this material in whole or
 * in part without a valid written license from Splunk Inc. is PROHIBITED.
 */
e.exports=function(e){var t={};function r(n){if(t[n])return t[n].exports;var o=t[n]={i:n,l:!1,exports:{}};return e[n].call(o.exports,o,o.exports,r),o.l=!0,o.exports}return r.m=e,r.c=t,r.d=function(e,t,n){r.o(e,t)||Object.defineProperty(e,t,{enumerable:!0,get:n})},r.r=function(e){"undefined"!=typeof Symbol&&Symbol.toStringTag&&Object.defineProperty(e,Symbol.toStringTag,{value:"Module"}),Object.defineProperty(e,"__esModule",{value:!0})},r.t=function(e,t){if(1&t&&(e=r(e)),8&t)return e;if(4&t&&"object"==typeof e&&e&&e.__esModule)return e;var n=Object.create(null);if(r.r(n),Object.defineProperty(n,"default",{enumerable:!0,value:e}),2&t&&"string"!=typeof e)for(var o in e)r.d(n,o,function(t){return e[t]}.bind(null,o));return n},r.n=function(e){var t=e&&e.__esModule?function(){return e.default}:function(){return e};return r.d(t,"a",t),t},r.o=function(e,t){return Object.prototype.hasOwnProperty.call(e,t)},r.p="",r(r.s=9)}([function(e,t){e.exports=r(0)},function(e,t){e.exports=r(26)},function(e,t){e.exports=r(30)},function(e,t){e.exports=r(7)},function(e,t){e.exports=r(34)},function(e,t){e.exports=r(150)},function(e,t){e.exports=r(249)},function(e,t){e.exports=r(278)},function(e,t){e.exports=r(486)},function(e,r,n){"use strict";n.r(r),n.d(r,"loadShellApp",(function(){return $}));var o=n(2),i=n.n(o),a=n(0),s=n.n(a),c=n(6),l=n.n(c),u=n(7),f=n.n(u),d=n(3),p=n(8),m=n(4),b=n(1),w=n(5);function y(e,t){var r=Object.keys(e);if(Object.getOwnPropertySymbols){var n=Object.getOwnPropertySymbols(e);t&&(n=n.filter((function(t){return Object.getOwnPropertyDescriptor(e,t).enumerable}))),r.push.apply(r,n)}return r}function g(e){for(var t=1;t<arguments.length;t++){var r=null!=arguments[t]?arguments[t]:{};t%2?y(Object(r),!0).forEach((function(t){i()(e,t,r[t])})):Object.getOwnPropertyDescriptors?Object.defineProperties(e,Object.getOwnPropertyDescriptors(r)):y(Object(r)).forEach((function(t){Object.defineProperty(e,t,Object.getOwnPropertyDescriptor(r,t))}))}return e}const h=Object(b.createURL)("/error"),O=Object(b.createStaticURL)("build/pages/enterprise/remoteApps"),v=Object(b.createRESTURL)("properties/web/remoteUI?output_mode=json");function j(e,t){const r=e.entry.find(e=>e.name===t);return r?r.content:null}function E(){const e=window.location.href;window.history.pushState({},"",e),window.location.assign(h)}const P=e=>{const{remoteConfig:t,singletonLibs:r}=e,{remoteAndManifests:n,loading:o,error:i}=Object(p.useRemotes)([t],r);if(o)return s.a.createElement("div",{id:"placeholder-main-section-body"},Object(d._)("Loading..."));!i&&n.length||E();const{remote:a,manifest:c}=n[0];return s.a.createElement("div",{id:"shell-success"},s.a.createElement("div",{"data-test-name":"rm-root","data-test-location":(t.isExternalRemote?"external":"local")+"-remote-app"},s.a.createElement(a.root,{key:"rm-root-"+c.id})))},S={family:"enterprise",colorScheme:"light",density:"comfortable"},x={family:"enterprise",colorScheme:"dark",density:"comfortable"};function R(e,t){var r=Object.keys(e);if(Object.getOwnPropertySymbols){var n=Object.getOwnPropertySymbols(e);t&&(n=n.filter((function(t){return Object.getOwnPropertyDescriptor(e,t).enumerable}))),r.push.apply(r,n)}return r}const $=async e=>{let{remoteConfig:r,singletonLibs:n,layoutOptions:o={}}=e;try{const e=function(e,t){const r=g({},e);let n=j(t,"remoteRoot"),o=j(t,"optInRemoteUI"),i=j(t,"allowExternalRemote");o=o&&Object(w.normalizeBoolean)(o.toLowerCase()),i=i&&Object(w.normalizeBoolean)(i.toLowerCase());const a=!Object(w.normalizeBoolean)(e.forceLoadFromSplunkHome);return i&&o&&a?r.isExternalRemote=!0:(n=Object(b.createStaticURL)(e.localRoot||O),r.isExternalRemote=!1),r.remoteRoot=n+"/"+(e.bucketPath||e.id)+"/"+e.version,r}(r,await(async()=>{try{const e=await t(v,g({},m.defaultFetchInit));return await Object(m.handleResponse)(200)(e)}catch(e){throw Object(m.handleError)(_("Couldn't get web.conf settings")),e}})()),a=document.querySelector(".preload");if(!a)throw new Error("Element: .preload could not be found");a.parentNode.removeChild(a),l()(s.a.createElement(f.a,window.__splunk_page_theme__&&"dark"===window.__splunk_page_theme__?x:S,s.a.createElement(P,{remoteConfig:e,singletonLibs:n})),function(e){for(var t=1;t<arguments.length;t++){var r=null!=arguments[t]?arguments[t]:{};t%2?R(Object(r),!0).forEach((function(t){i()(e,t,r[t])})):Object.getOwnPropertyDescriptors?Object.defineProperties(e,Object.getOwnPropertyDescriptors(r)):R(Object(r)).forEach((function(t){Object.defineProperty(e,t,Object.getOwnPropertyDescriptor(r,t))}))}return e}({pageTitle:Object(d._)("Splunk")},o))}catch(e){return void E()}}}])}).call(this,r(31))},486:function(e,t,r){(function(t){
/*!
 * Copyright © 2018 Splunk Inc.
 * SPLUNK CONFIDENTIAL – Use or disclosure of this material in whole or
 * in part without a valid written license from Splunk Inc. is PROHIBITED.
 */
e.exports=function(e){var t={};function r(n){if(t[n])return t[n].exports;var o=t[n]={i:n,l:!1,exports:{}};return e[n].call(o.exports,o,o.exports,r),o.l=!0,o.exports}return r.m=e,r.c=t,r.d=function(e,t,n){r.o(e,t)||Object.defineProperty(e,t,{enumerable:!0,get:n})},r.r=function(e){"undefined"!=typeof Symbol&&Symbol.toStringTag&&Object.defineProperty(e,Symbol.toStringTag,{value:"Module"}),Object.defineProperty(e,"__esModule",{value:!0})},r.t=function(e,t){if(1&t&&(e=r(e)),8&t)return e;if(4&t&&"object"==typeof e&&e&&e.__esModule)return e;var n=Object.create(null);if(r.r(n),Object.defineProperty(n,"default",{enumerable:!0,value:e}),2&t&&"string"!=typeof e)for(var o in e)r.d(n,o,function(t){return e[t]}.bind(null,o));return n},r.n=function(e){var t=e&&e.__esModule?function(){return e.default}:function(){return e};return r.d(t,"a",t),t},r.o=function(e,t){return Object.prototype.hasOwnProperty.call(e,t)},r.p="",r(r.s=2)}([function(e,t){e.exports=r(0)},function(e,t){e.exports=r(30)},function(e,r,n){"use strict";n.r(r),n.d(r,"createLoader",(function(){return l})),n.d(r,"useRemotes",(function(){return f})),n.d(r,"createRemote",(function(){return d}));var o=n(1),i=n.n(o);const a=new RegExp("[0-9]+.latest"),s=()=>Math.random().toString(36).substring(7);class c extends class{async loadManifest(e,r,n="manifest.json"){try{const e=await t(`${r}/${n}?_=${s()}`);if(200!==e.status)throw new Error(`Invalid response status code from ${r}: ${e.status}`);return await e.json()}catch(t){throw new Error(`Error fetching manifest for remote ${e}: ${t.message}`)}}async resolveLatest(e,r){let n=r;if(a.test(n)){let o;try{if(o=await t(`${n}/version.json?_=${s()}`),200!==o.status)throw new Error(`Invalid response status code from ${r}: ${o.status}`)}catch(t){throw new Error(`Error fetching version number for remote ${e}: ${t.message}`)}try{const t=await o.json();if(null==(null==t?void 0:t.latest))throw new Error(`Error resolving latest version for remote ${e}. No version file found at ${r}`);n=r.replace(a,t.latest)}catch(t){throw new Error(`Error parsing version number for remote ${e}: ${t.message}`)}}return n}async loadRemotes(e,t){return(await Promise.all(t.map(async t=>{try{const r=await this.resolveLatest(t.id,t.remoteRoot),n=await this.loadManifest(t.id,r,t.manifestName);return this.loadRemote(r,n,e)}catch{return null}}))).filter(e=>e)}}{constructor(...e){super(...e),i()(this,"modulesByName",new Map)}loadRemote(e,t){return new Promise((r,n)=>{const o="script_"+t.id,i=document.getElementById(o);i&&i.remove();const a=document.createElement("script");a.id=o,a.async=!0,a.onload=()=>{const o=t.id,i=this.modulesByName.get(o);if(i){const n=(i.default||i)({remoteRoot:e});r({remote:n,manifest:t})}else n(new Error(`failed to find module ${o} in ${e}`))},a.onerror=r=>{n(new Error(`failed to load ${t.id} from ${e} error: ${r.message}`))},a.src=`${e}/${t.main||"index.js"}`,document.head.appendChild(a)})}async loadRemotes(e,t){const r=((e,t=new Map)=>{const{define:r}=window;return window.define=(r,n,o)=>{if("string"!=typeof r)throw new Error("Error loading module, anonymous AMD modules cannot be loaded using this approach.");const i=o(...n.map(t=>e[t]));if(t.has(r))throw new Error(`Error loading module ${r}. A module with the same name is already loaded. Duplicate names not allowed.`);t.set(r,i)},()=>{window.define=r}})(e,this.modulesByName);try{return await super.loadRemotes(e,t)}finally{r()}}}const l=()=>new c;var u=n(0);function f(e,t){const[r,n]=Object(u.useState)({remoteAndManifests:[],loading:!0,error:null});return Object(u.useEffect)(()=>{n({remoteAndManifests:[],loading:!0,error:null});let r=!1;return l().loadRemotes(t,e).then(e=>{r||n({remoteAndManifests:e,loading:!1,error:null})}).catch(e=>{r||n({remoteAndManifests:[],loading:!1,error:e})}),()=>{r=!0}},[]),r}function d(e,t){return r=>(t(r),e)}}])}).call(this,r(31))}});