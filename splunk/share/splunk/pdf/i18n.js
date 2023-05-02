// get locale data, fallback to use en-US for undefined locale
var LOCALES = {
        'en_US': {"exp_symbol":"E","scientific_format":"#E0","percent_format":"#,##0%","date_formats":{"long":{"format":"%(MMMM)s %(d)s, %(y)s","pattern":"MMMM d, y"},"medium":{"format":"%(MMM)s %(d)s, %(y)s","pattern":"MMM d, y"},"short":{"format":"%(M)s/%(d)s/%(yy)s","pattern":"M/d/yy"},"full":{"format":"%(EEEE)s, %(MMMM)s %(d)s, %(y)s","pattern":"EEEE, MMMM d, y"}},"time_formats":{"long":{"format":"%(h)s:%(mm)s:%(ss)s %(a)s %(z)s","pattern":"h:mm:ss a z"},"medium":{"format":"%(h)s:%(mm)s:%(ss)s %(a)s","pattern":"h:mm:ss a"},"short":{"format":"%(h)s:%(mm)s %(a)s","pattern":"h:mm a"},"full":{"format":"%(h)s:%(mm)s:%(ss)s %(a)s %(zzzz)s","pattern":"h:mm:ss a zzzz"}},"quarters":{"format":{"abbreviated":{"1":"Q1","2":"Q2","3":"Q3","4":"Q4"},"narrow":{"1":"1","2":"2","3":"3","4":"4"},"wide":{"1":"1st quarter","2":"2nd quarter","3":"3rd quarter","4":"4th quarter"}},"stand-alone":{"abbreviated":{"1":"Q1","2":"Q2","3":"Q3","4":"Q4"},"narrow":{"1":"1","2":"2","3":"3","4":"4"},"wide":{"1":"1st quarter","2":"2nd quarter","3":"3rd quarter","4":"4th quarter"}}},"group_symbol":",","days":{"format":{"wide":{"0":"Monday","1":"Tuesday","2":"Wednesday","3":"Thursday","4":"Friday","5":"Saturday","6":"Sunday"},"abbreviated":{"0":"Mon","1":"Tue","2":"Wed","3":"Thu","4":"Fri","5":"Sat","6":"Sun"},"narrow":{"0":"M","1":"T","2":"W","3":"T","4":"F","5":"S","6":"S"},"short":{"0":"Mo","1":"Tu","2":"We","3":"Th","4":"Fr","5":"Sa","6":"Su"}},"stand-alone":{"wide":{"0":"Monday","1":"Tuesday","2":"Wednesday","3":"Thursday","4":"Friday","5":"Saturday","6":"Sunday"},"abbreviated":{"0":"Mon","1":"Tue","2":"Wed","3":"Thu","4":"Fri","5":"Sat","6":"Sun"},"narrow":{"0":"M","1":"T","2":"W","3":"T","4":"F","5":"S","6":"S"},"short":{"0":"Mo","1":"Tu","2":"We","3":"Th","4":"Fr","5":"Sa","6":"Su"}}},"decimal_symbol":".","months":{"format":{"abbreviated":{"1":"Jan","2":"Feb","3":"Mar","4":"Apr","5":"May","6":"Jun","7":"Jul","8":"Aug","9":"Sep","10":"Oct","11":"Nov","12":"Dec"},"narrow":{"1":"J","2":"F","3":"M","4":"A","5":"M","6":"J","7":"J","8":"A","9":"S","10":"O","11":"N","12":"D"},"wide":{"1":"January","2":"February","3":"March","4":"April","5":"May","6":"June","7":"July","8":"August","9":"September","10":"October","11":"November","12":"December"}},"stand-alone":{"abbreviated":{"1":"Jan","2":"Feb","3":"Mar","4":"Apr","5":"May","6":"Jun","7":"Jul","8":"Aug","9":"Sep","10":"Oct","11":"Nov","12":"Dec"},"narrow":{"1":"J","2":"F","3":"M","4":"A","5":"M","6":"J","7":"J","8":"A","9":"S","10":"O","11":"N","12":"D"},"wide":{"1":"January","2":"February","3":"March","4":"April","5":"May","6":"June","7":"July","8":"August","9":"September","10":"October","11":"November","12":"December"}}},"minus_sign":"-","min_week_days":1,"first_week_day":6,"periods":{"pm":"PM","evening1":"evening","morning1":"morning","afternoon1":"afternoon","am":"AM","night1":"night","noon":"noon","midnight":"midnight"},"datetime_formats":{"null":"{1} {0}"},"number_format":"#,##0.###","locale_name":"en_US","plus_sign":"+","eras":{"abbreviated":{"0":"BC","1":"AD"},"narrow":{"0":"B","1":"A"},"wide":{"0":"Before Christ","1":"Anno Domini"}}},
        'fr_FR': {"exp_symbol":"E","scientific_format":"#E0","percent_format":"#,##0 %","date_formats":{"long":{"format":"%(d)s %(MMMM)s %(y)s","pattern":"d MMMM y"},"medium":{"format":"%(d)s %(MMM)s %(y)s","pattern":"d MMM y"},"short":{"format":"%(dd)s/%(MM)s/%(y)s","pattern":"dd/MM/y"},"full":{"format":"%(EEEE)s %(d)s %(MMMM)s %(y)s","pattern":"EEEE d MMMM y"}},"time_formats":{"long":{"format":"%(HH)s:%(mm)s:%(ss)s %(z)s","pattern":"HH:mm:ss z"},"medium":{"format":"%(HH)s:%(mm)s:%(ss)s","pattern":"HH:mm:ss"},"short":{"format":"%(HH)s:%(mm)s","pattern":"HH:mm"},"full":{"format":"%(HH)s:%(mm)s:%(ss)s %(zzzz)s","pattern":"HH:mm:ss zzzz"}},"quarters":{"format":{"abbreviated":{"1":"T1","2":"T2","3":"T3","4":"T4"},"narrow":{"1":"1","2":"2","3":"3","4":"4"},"wide":{"1":"1er trimestre","2":"2e trimestre","3":"3e trimestre","4":"4e trimestre"}},"stand-alone":{"abbreviated":{"1":"T1","2":"T2","3":"T3","4":"T4"},"narrow":{"1":"1","2":"2","3":"3","4":"4"},"wide":{"1":"1er trimestre","2":"2e trimestre","3":"3e trimestre","4":"4e trimestre"}}},"group_symbol":" ","days":{"format":{"wide":{"0":"lundi","1":"mardi","2":"mercredi","3":"jeudi","4":"vendredi","5":"samedi","6":"dimanche"},"abbreviated":{"0":"lun.","1":"mar.","2":"mer.","3":"jeu.","4":"ven.","5":"sam.","6":"dim."},"narrow":{"0":"L","1":"M","2":"M","3":"J","4":"V","5":"S","6":"D"},"short":{"0":"lu","1":"ma","2":"me","3":"je","4":"ve","5":"sa","6":"di"}},"stand-alone":{"wide":{"0":"lundi","1":"mardi","2":"mercredi","3":"jeudi","4":"vendredi","5":"samedi","6":"dimanche"},"abbreviated":{"0":"lun.","1":"mar.","2":"mer.","3":"jeu.","4":"ven.","5":"sam.","6":"dim."},"narrow":{"0":"L","1":"M","2":"M","3":"J","4":"V","5":"S","6":"D"},"short":{"0":"lu","1":"ma","2":"me","3":"je","4":"ve","5":"sa","6":"di"}}},"decimal_symbol":",","months":{"format":{"abbreviated":{"1":"janv.","2":"févr.","3":"mars","4":"avr.","5":"mai","6":"juin","7":"juil.","8":"août","9":"sept.","10":"oct.","11":"nov.","12":"déc."},"narrow":{"1":"J","2":"F","3":"M","4":"A","5":"M","6":"J","7":"J","8":"A","9":"S","10":"O","11":"N","12":"D"},"wide":{"1":"janvier","2":"février","3":"mars","4":"avril","5":"mai","6":"juin","7":"juillet","8":"août","9":"septembre","10":"octobre","11":"novembre","12":"décembre"}},"stand-alone":{"abbreviated":{"1":"janv.","2":"févr.","3":"mars","4":"avr.","5":"mai","6":"juin","7":"juil.","8":"août","9":"sept.","10":"oct.","11":"nov.","12":"déc."},"narrow":{"1":"J","2":"F","3":"M","4":"A","5":"M","6":"J","7":"J","8":"A","9":"S","10":"O","11":"N","12":"D"},"wide":{"1":"janvier","2":"février","3":"mars","4":"avril","5":"mai","6":"juin","7":"juillet","8":"août","9":"septembre","10":"octobre","11":"novembre","12":"décembre"}}},"minus_sign":"-","min_week_days":4,"first_week_day":0,"periods":{"pm":"PM","evening1":"soir","morning1":"matin","afternoon1":"après-midi","am":"AM","night1":"nuit","noon":"midi","midnight":"minuit"},"datetime_formats":{"null":"{1} {0}"},"number_format":"#,##0.###","locale_name":"fr_FR","plus_sign":"+","eras":{"abbreviated":{"0":"av. J.-C.","1":"ap. J.-C."},"narrow":{"0":"av. J.-C.","1":"ap. J.-C."},"wide":{"0":"avant Jésus-Christ","1":"après Jésus-Christ"}}},
        'de_DE': {"exp_symbol":"E","scientific_format":"#E0","percent_format":"#,##0 %","date_formats":{"long":{"format":"%(d)s. %(MMMM)s %(y)s","pattern":"d. MMMM y"},"medium":{"format":"%(dd)s.%(MM)s.%(y)s","pattern":"dd.MM.y"},"short":{"format":"%(dd)s.%(MM)s.%(yy)s","pattern":"dd.MM.yy"},"full":{"format":"%(EEEE)s, %(d)s. %(MMMM)s %(y)s","pattern":"EEEE, d. MMMM y"}},"time_formats":{"long":{"format":"%(HH)s:%(mm)s:%(ss)s %(z)s","pattern":"HH:mm:ss z"},"medium":{"format":"%(HH)s:%(mm)s:%(ss)s","pattern":"HH:mm:ss"},"short":{"format":"%(HH)s:%(mm)s","pattern":"HH:mm"},"full":{"format":"%(HH)s:%(mm)s:%(ss)s %(zzzz)s","pattern":"HH:mm:ss zzzz"},"medium-microsecond":{"pattern":"HH:mm:ss_TTT","format":"%(HH)s:%(mm)s:%(ss)s%(_)s%(TTT)s"}},"quarters":{"format":{"abbreviated":{"1":"Q1","2":"Q2","3":"Q3","4":"Q4"},"narrow":{"1":"1","2":"2","3":"3","4":"4"},"wide":{"1":"1. Quartal","2":"2. Quartal","3":"3. Quartal","4":"4. Quartal"}},"stand-alone":{"abbreviated":{"1":"Q1","2":"Q2","3":"Q3","4":"Q4"},"narrow":{"1":"1","2":"2","3":"3","4":"4"},"wide":{"1":"1. Quartal","2":"2. Quartal","3":"3. Quartal","4":"4. Quartal"}}},"group_symbol":".","days":{"format":{"wide":{"0":"Montag","1":"Dienstag","2":"Mittwoch","3":"Donnerstag","4":"Freitag","5":"Samstag","6":"Sonntag"},"abbreviated":{"0":"Mo.","1":"Di.","2":"Mi.","3":"Do.","4":"Fr.","5":"Sa.","6":"So."},"narrow":{"0":"M","1":"D","2":"M","3":"D","4":"F","5":"S","6":"S"},"short":{"0":"Mo.","1":"Di.","2":"Mi.","3":"Do.","4":"Fr.","5":"Sa.","6":"So."}},"stand-alone":{"wide":{"0":"Montag","1":"Dienstag","2":"Mittwoch","3":"Donnerstag","4":"Freitag","5":"Samstag","6":"Sonntag"},"abbreviated":{"0":"Mo","1":"Di","2":"Mi","3":"Do","4":"Fr","5":"Sa","6":"So"},"narrow":{"0":"M","1":"D","2":"M","3":"D","4":"F","5":"S","6":"S"},"short":{"0":"Mo.","1":"Di.","2":"Mi.","3":"Do.","4":"Fr.","5":"Sa.","6":"So."}}},"decimal_symbol":",","months":{"format":{"abbreviated":{"1":"Jan.","2":"Feb.","3":"März","4":"Apr.","5":"Mai","6":"Juni","7":"Juli","8":"Aug.","9":"Sep.","10":"Okt.","11":"Nov.","12":"Dez."},"narrow":{"1":"J","2":"F","3":"M","4":"A","5":"M","6":"J","7":"J","8":"A","9":"S","10":"O","11":"N","12":"D"},"wide":{"1":"Januar","2":"Februar","3":"März","4":"April","5":"Mai","6":"Juni","7":"Juli","8":"August","9":"September","10":"Oktober","11":"November","12":"Dezember"}},"stand-alone":{"abbreviated":{"1":"Jan","2":"Feb","3":"Mär","4":"Apr","5":"Mai","6":"Jun","7":"Jul","8":"Aug","9":"Sep","10":"Okt","11":"Nov","12":"Dez"},"narrow":{"1":"J","2":"F","3":"M","4":"A","5":"M","6":"J","7":"J","8":"A","9":"S","10":"O","11":"N","12":"D"},"wide":{"1":"Januar","2":"Februar","3":"März","4":"April","5":"Mai","6":"Juni","7":"Juli","8":"August","9":"September","10":"Oktober","11":"November","12":"Dezember"}}},"minus_sign":"-","min_week_days":4,"first_week_day":0,"periods":{"night1":"Nacht","evening1":"Abend","morning2":"Vormittag","afternoon1":"Mittag","pm":"nachm.","am":"vorm.","morning1":"Morgen","afternoon2":"Nachmittag","midnight":"Mitternacht"},"datetime_formats":{"null":"{1} {0}"},"number_format":"#,##0.###","locale_name":"de_DE","plus_sign":"+","eras":{"abbreviated":{"0":"v. Chr.","1":"n. Chr."},"narrow":{"0":"v. Chr.","1":"n. Chr."},"wide":{"0":"v. Chr.","1":"n. Chr."}}},
        'it_IT': {"exp_symbol":"E","scientific_format":"#E0","percent_format":"#,##0%","date_formats":{"long":{"format":"%(d)s %(MMMM)s %(y)s","pattern":"d MMMM y"},"medium":{"format":"%(d)s %(MMM)s %(y)s","pattern":"d MMM y"},"short":{"format":"%(dd)s/%(MM)s/%(yy)s","pattern":"dd/MM/yy"},"full":{"format":"%(EEEE)s %(d)s %(MMMM)s %(y)s","pattern":"EEEE d MMMM y"}},"time_formats":{"long":{"format":"%(HH)s:%(mm)s:%(ss)s %(z)s","pattern":"HH:mm:ss z"},"medium":{"format":"%(HH)s:%(mm)s:%(ss)s","pattern":"HH:mm:ss"},"short":{"format":"%(HH)s:%(mm)s","pattern":"HH:mm"},"full":{"format":"%(HH)s:%(mm)s:%(ss)s %(zzzz)s","pattern":"HH:mm:ss zzzz"}},"quarters":{"format":{"abbreviated":{"1":"T1","2":"T2","3":"T3","4":"T4"},"narrow":{"1":"1","2":"2","3":"3","4":"4"},"wide":{"1":"1º trimestre","2":"2º trimestre","3":"3º trimestre","4":"4º trimestre"}},"stand-alone":{"abbreviated":{"1":"T1","2":"T2","3":"T3","4":"T4"},"narrow":{"1":"1","2":"2","3":"3","4":"4"},"wide":{"1":"1º trimestre","2":"2º trimestre","3":"3º trimestre","4":"4º trimestre"}}},"group_symbol":".","days":{"format":{"wide":{"0":"lunedì","1":"martedì","2":"mercoledì","3":"giovedì","4":"venerdì","5":"sabato","6":"domenica"},"abbreviated":{"0":"lun","1":"mar","2":"mer","3":"gio","4":"ven","5":"sab","6":"dom"},"narrow":{"0":"L","1":"M","2":"M","3":"G","4":"V","5":"S","6":"D"},"short":{"0":"lun","1":"mar","2":"mer","3":"gio","4":"ven","5":"sab","6":"dom"}},"stand-alone":{"wide":{"0":"lunedì","1":"martedì","2":"mercoledì","3":"giovedì","4":"venerdì","5":"sabato","6":"domenica"},"abbreviated":{"0":"lun","1":"mar","2":"mer","3":"gio","4":"ven","5":"sab","6":"dom"},"narrow":{"0":"L","1":"M","2":"M","3":"G","4":"V","5":"S","6":"D"},"short":{"0":"lun","1":"mar","2":"mer","3":"gio","4":"ven","5":"sab","6":"dom"}}},"decimal_symbol":",","months":{"format":{"abbreviated":{"1":"gen","2":"feb","3":"mar","4":"apr","5":"mag","6":"giu","7":"lug","8":"ago","9":"set","10":"ott","11":"nov","12":"dic"},"narrow":{"1":"G","2":"F","3":"M","4":"A","5":"M","6":"G","7":"L","8":"A","9":"S","10":"O","11":"N","12":"D"},"wide":{"1":"gennaio","2":"febbraio","3":"marzo","4":"aprile","5":"maggio","6":"giugno","7":"luglio","8":"agosto","9":"settembre","10":"ottobre","11":"novembre","12":"dicembre"}},"stand-alone":{"abbreviated":{"1":"gen","2":"feb","3":"mar","4":"apr","5":"mag","6":"giu","7":"lug","8":"ago","9":"set","10":"ott","11":"nov","12":"dic"},"narrow":{"1":"G","2":"F","3":"M","4":"A","5":"M","6":"G","7":"L","8":"A","9":"S","10":"O","11":"N","12":"D"},"wide":{"1":"gennaio","2":"febbraio","3":"marzo","4":"aprile","5":"maggio","6":"giugno","7":"luglio","8":"agosto","9":"settembre","10":"ottobre","11":"novembre","12":"dicembre"}}},"minus_sign":"-","min_week_days":4,"first_week_day":0,"periods":{"pm":"PM","evening1":"sera","morning1":"mattina","afternoon1":"pomeriggio","am":"AM","night1":"notte","noon":"mezzogiorno","midnight":"mezzanotte"},"datetime_formats":{"null":"{1} {0}"},"number_format":"#,##0.###","locale_name":"it_IT","plus_sign":"+","eras":{"abbreviated":{"0":"a.C.","1":"d.C."},"narrow":{"0":"aC","1":"dC"},"wide":{"0":"avanti Cristo","1":"dopo Cristo"}}},
        'ja_JP': {"exp_symbol":"E","scientific_format":"#E0","percent_format":"#,##0%","date_formats":{"long":{"format":"%(y)s年%(M)s月%(d)s日","pattern":"y年M月d日"},"medium":{"format":"%(y)s/%(MM)s/%(dd)s","pattern":"y/MM/dd"},"short":{"format":"%(y)s/%(MM)s/%(dd)s","pattern":"y/MM/dd"},"full":{"format":"%(y)s年%(M)s月%(d)s日%(EEEE)s","pattern":"y年M月d日EEEE"}},"time_formats":{"long":{"format":"%(H)s:%(mm)s:%(ss)s %(z)s","pattern":"H:mm:ss z"},"medium":{"format":"%(H)s:%(mm)s:%(ss)s","pattern":"H:mm:ss"},"short":{"format":"%(H)s:%(mm)s","pattern":"H:mm"},"full":{"format":"%(H)s時%(mm)s分%(ss)s秒 %(zzzz)s","pattern":"H時mm分ss秒 zzzz"}},"quarters":{"format":{"abbreviated":{"1":"Q1","2":"Q2","3":"Q3","4":"Q4"},"narrow":{"1":"1","2":"2","3":"3","4":"4"},"wide":{"1":"第1四半期","2":"第2四半期","3":"第3四半期","4":"第4四半期"}},"stand-alone":{"abbreviated":{"1":"Q1","2":"Q2","3":"Q3","4":"Q4"},"narrow":{"1":"1","2":"2","3":"3","4":"4"},"wide":{"1":"第1四半期","2":"第2四半期","3":"第3四半期","4":"第4四半期"}}},"group_symbol":",","days":{"format":{"wide":{"0":"月曜日","1":"火曜日","2":"水曜日","3":"木曜日","4":"金曜日","5":"土曜日","6":"日曜日"},"abbreviated":{"0":"月","1":"火","2":"水","3":"木","4":"金","5":"土","6":"日"},"narrow":{"0":"月","1":"火","2":"水","3":"木","4":"金","5":"土","6":"日"},"short":{"0":"月","1":"火","2":"水","3":"木","4":"金","5":"土","6":"日"}},"stand-alone":{"wide":{"0":"月曜日","1":"火曜日","2":"水曜日","3":"木曜日","4":"金曜日","5":"土曜日","6":"日曜日"},"abbreviated":{"0":"月","1":"火","2":"水","3":"木","4":"金","5":"土","6":"日"},"narrow":{"0":"月","1":"火","2":"水","3":"木","4":"金","5":"土","6":"日"},"short":{"0":"月","1":"火","2":"水","3":"木","4":"金","5":"土","6":"日"}}},"decimal_symbol":".","months":{"format":{"abbreviated":{"1":"1月","2":"2月","3":"3月","4":"4月","5":"5月","6":"6月","7":"7月","8":"8月","9":"9月","10":"10月","11":"11月","12":"12月"},"narrow":{"1":"1","2":"2","3":"3","4":"4","5":"5","6":"6","7":"7","8":"8","9":"9","10":"10","11":"11","12":"12"},"wide":{"1":"1月","2":"2月","3":"3月","4":"4月","5":"5月","6":"6月","7":"7月","8":"8月","9":"9月","10":"10月","11":"11月","12":"12月"}},"stand-alone":{"abbreviated":{"1":"1月","2":"2月","3":"3月","4":"4月","5":"5月","6":"6月","7":"7月","8":"8月","9":"9月","10":"10月","11":"11月","12":"12月"},"narrow":{"1":"1","2":"2","3":"3","4":"4","5":"5","6":"6","7":"7","8":"8","9":"9","10":"10","11":"11","12":"12"},"wide":{"1":"1月","2":"2月","3":"3月","4":"4月","5":"5月","6":"6月","7":"7月","8":"8月","9":"9月","10":"10月","11":"11月","12":"12月"}}},"minus_sign":"-","min_week_days":1,"first_week_day":6,"periods":{"evening1":"夕方","night2":"夜中","morning1":"朝","pm":"午後","afternoon1":"昼","am":"午前","night1":"夜","noon":"正午","midnight":"真夜中"},"datetime_formats":{"null":"{1} {0}"},"number_format":"#,##0.###","locale_name":"ja_JP","plus_sign":"+","eras":{"abbreviated":{"0":"紀元前","1":"西暦"},"narrow":{"0":"BC","1":"AD"},"wide":{"0":"紀元前","1":"西暦"}}},
        'ko_KR': {"exp_symbol":"E","scientific_format":"#E0","percent_format":"#,##0%","date_formats":{"long":{"format":"%(y)s년 %(M)s월 %(d)s일","pattern":"y년 M월 d일"},"medium":{"pattern":"yyyy/MM/dd","format":"%(yyyy)s/%(MM)s/%(dd)s"},"short":{"pattern":"yy/MM/dd","format":"%(yy)s/%(MM)s/%(dd)s"},"full":{"format":"%(y)s년 %(M)s월 %(d)s일 %(EEEE)s","pattern":"y년 M월 d일 EEEE"}},"time_formats":{"long":{"format":"%(a)s %(h)s시 %(m)s분 %(s)s초 %(z)s","pattern":"a h시 m분 s초 z"},"medium":{"pattern":"H:mm:ss","format":"%(H)s:%(mm)s:%(ss)s"},"short":{"pattern":"H:mm","format":"%(H)s:%(mm)s"},"full":{"format":"%(a)s %(h)s시 %(m)s분 %(s)s초 %(zzzz)s","pattern":"a h시 m분 s초 zzzz"}},"quarters":{"format":{"abbreviated":{"1":"1분기","2":"2분기","3":"3분기","4":"4분기"},"narrow":{"1":"1","2":"2","3":"3","4":"4"},"wide":{"1":"제 1/4분기","2":"제 2/4분기","3":"제 3/4분기","4":"제 4/4분기"}},"stand-alone":{"abbreviated":{"1":"1분기","2":"2분기","3":"3분기","4":"4분기"},"narrow":{"1":"1","2":"2","3":"3","4":"4"},"wide":{"1":"제 1/4분기","2":"제 2/4분기","3":"제 3/4분기","4":"제 4/4분기"}}},"group_symbol":",","days":{"format":{"wide":{"0":"월요일","1":"화요일","2":"수요일","3":"목요일","4":"금요일","5":"토요일","6":"일요일"},"abbreviated":{"0":"월","1":"화","2":"수","3":"목","4":"금","5":"토","6":"일"},"narrow":{"0":"월","1":"화","2":"수","3":"목","4":"금","5":"토","6":"일"},"short":{"0":"월","1":"화","2":"수","3":"목","4":"금","5":"토","6":"일"}},"stand-alone":{"wide":{"0":"월요일","1":"화요일","2":"수요일","3":"목요일","4":"금요일","5":"토요일","6":"일요일"},"abbreviated":{"0":"월","1":"화","2":"수","3":"목","4":"금","5":"토","6":"일"},"narrow":{"0":"월","1":"화","2":"수","3":"목","4":"금","5":"토","6":"일"},"short":{"0":"월","1":"화","2":"수","3":"목","4":"금","5":"토","6":"일"}}},"decimal_symbol":".","months":{"format":{"abbreviated":{"1":"1월","2":"2월","3":"3월","4":"4월","5":"5월","6":"6월","7":"7월","8":"8월","9":"9월","10":"10월","11":"11월","12":"12월"},"narrow":{"1":"1월","2":"2월","3":"3월","4":"4월","5":"5월","6":"6월","7":"7월","8":"8월","9":"9월","10":"10월","11":"11월","12":"12월"},"wide":{"1":"1월","2":"2월","3":"3월","4":"4월","5":"5월","6":"6월","7":"7월","8":"8월","9":"9월","10":"10월","11":"11월","12":"12월"}},"stand-alone":{"abbreviated":{"1":"1월","2":"2월","3":"3월","4":"4월","5":"5월","6":"6월","7":"7월","8":"8월","9":"9월","10":"10월","11":"11월","12":"12월"},"narrow":{"1":"1월","2":"2월","3":"3월","4":"4월","5":"5월","6":"6월","7":"7월","8":"8월","9":"9월","10":"10월","11":"11월","12":"12월"},"wide":{"1":"1월","2":"2월","3":"3월","4":"4월","5":"5월","6":"6월","7":"7월","8":"8월","9":"9월","10":"10월","11":"11월","12":"12월"}}},"minus_sign":"-","min_week_days":1,"first_week_day":6,"periods":{"evening1":"저녁","morning2":"오전","morning1":"새벽","pm":"오후","midnight":"자정","night1":"밤","noon":"정오","am":"오전","afternoon1":"오후"},"datetime_formats":{"null":"{1} {0}"},"number_format":"#,##0.###","locale_name":"ko_KR","plus_sign":"+","eras":{"abbreviated":{"0":"BC","1":"AD"},"narrow":{"0":"BC","1":"AD"},"wide":{"0":"기원전","1":"서기"}}},
        'zh_CN': {"exp_symbol":"E","scientific_format":"#E0","percent_format":"#,##0%","date_formats":{"long":{"format":"%(y)s年%(M)s月%(d)s日","pattern":"y年M月d日"},"medium":{"pattern":"yyyy/MM/dd","format":"%(yyyy)s/%(MM)s/%(dd)s"},"short":{"pattern":"yy/MM/dd","format":"%(yy)s/%(MM)s/%(dd)s"},"full":{"format":"%(y)s年%(M)s月%(d)s日%(EEEE)s","pattern":"y年M月d日EEEE"}},"time_formats":{"long":{"format":"%(z)s %(a)s%(h)s:%(mm)s:%(ss)s","pattern":"z ah:mm:ss"},"medium":{"pattern":"H:mm:ss","format":"%(H)s:%(mm)s:%(ss)s"},"short":{"pattern":"H:mm","format":"%(H)s:%(mm)s"},"full":{"format":"%(zzzz)s %(a)s%(h)s:%(mm)s:%(ss)s","pattern":"zzzz ah:mm:ss"}},"quarters":{"format":{"abbreviated":{"1":"1季度","2":"2季度","3":"3季度","4":"4季度"},"narrow":{"1":"1","2":"2","3":"3","4":"4"},"wide":{"1":"第一季度","2":"第二季度","3":"第三季度","4":"第四季度"}},"stand-alone":{"abbreviated":{"1":"1季度","2":"2季度","3":"3季度","4":"4季度"},"narrow":{"1":"1","2":"2","3":"3","4":"4"},"wide":{"1":"第一季度","2":"第二季度","3":"第三季度","4":"第四季度"}}},"group_symbol":",","days":{"format":{"wide":{"0":"星期一","1":"星期二","2":"星期三","3":"星期四","4":"星期五","5":"星期六","6":"星期日"},"abbreviated":{"0":"周一","1":"周二","2":"周三","3":"周四","4":"周五","5":"周六","6":"周日"},"narrow":{"0":"一","1":"二","2":"三","3":"四","4":"五","5":"六","6":"日"},"short":{"0":"周一","1":"周二","2":"周三","3":"周四","4":"周五","5":"周六","6":"周日"}},"stand-alone":{"wide":{"0":"星期一","1":"星期二","2":"星期三","3":"星期四","4":"星期五","5":"星期六","6":"星期日"},"abbreviated":{"0":"周一","1":"周二","2":"周三","3":"周四","4":"周五","5":"周六","6":"周日"},"narrow":{"0":"一","1":"二","2":"三","3":"四","4":"五","5":"六","6":"日"},"short":{"0":"周一","1":"周二","2":"周三","3":"周四","4":"周五","5":"周六","6":"周日"}}},"decimal_symbol":".","months":{"format":{"abbreviated":{"1":"1月","2":"2月","3":"3月","4":"4月","5":"5月","6":"6月","7":"7月","8":"8月","9":"9月","10":"10月","11":"11月","12":"12月"},"narrow":{"1":"1","2":"2","3":"3","4":"4","5":"5","6":"6","7":"7","8":"8","9":"9","10":"10","11":"11","12":"12"},"wide":{"1":"一月","2":"二月","3":"三月","4":"四月","5":"五月","6":"六月","7":"七月","8":"八月","9":"九月","10":"十月","11":"十一月","12":"十二月"}},"stand-alone":{"abbreviated":{"1":"1月","2":"2月","3":"3月","4":"4月","5":"5月","6":"6月","7":"7月","8":"8月","9":"9月","10":"10月","11":"11月","12":"12月"},"narrow":{"1":"1","2":"2","3":"3","4":"4","5":"5","6":"6","7":"7","8":"8","9":"9","10":"10","11":"11","12":"12"},"wide":{"1":"一月","2":"二月","3":"三月","4":"四月","5":"五月","6":"六月","7":"七月","8":"八月","9":"九月","10":"十月","11":"十一月","12":"十二月"}}},"minus_sign":"-","min_week_days":1,"first_week_day":6,"periods":{"night1":"凌晨","evening1":"晚上","morning2":"上午","afternoon1":"中午","pm":"下午","am":"上午","morning1":"早上","afternoon2":"下午","midnight":"午夜"},"datetime_formats":{"null":"{1} {0}"},"number_format":"#,##0.###","locale_name":"zh_CN","plus_sign":"+","eras":{"abbreviated":{"0":"公元前","1":"公元"},"narrow":{"0":"公元前","1":"公元"},"wide":{"0":"公元前","1":"公元"}}},
        'zh_TW': {"exp_symbol":"E","scientific_format":"#E0","percent_format":"#,##0%","date_formats":{"long":{"format":"%(y)s年%(M)s月%(d)s日","pattern":"y年M月d日"},"medium":{"pattern":"yyyy/MM/dd","format":"%(yyyy)s/%(MM)s/%(dd)s"},"short":{"pattern":"yy/MM/dd","format":"%(yy)s/%(MM)s/%(dd)s"},"full":{"format":"%(y)s年%(M)s月%(d)s日 %(EEEE)s","pattern":"y年M月d日 EEEE"}},"time_formats":{"long":{"format":"%(a)s%(h)s:%(mm)s:%(ss)s [%(z)s]","pattern":"ah:mm:ss [z]"},"medium":{"pattern":"H:mm:ss","format":"%(H)s:%(mm)s:%(ss)s"},"short":{"pattern":"H:mm","format":"%(H)s:%(mm)s"},"full":{"format":"%(a)s%(h)s:%(mm)s:%(ss)s [%(zzzz)s]","pattern":"ah:mm:ss [zzzz]"}},"quarters":{"format":{"abbreviated":{"1":"第1季","2":"第2季","3":"第3季","4":"第4季"},"narrow":{"1":"1","2":"2","3":"3","4":"4"},"wide":{"1":"第1季","2":"第2季","3":"第3季","4":"第4季"}},"stand-alone":{"abbreviated":{"1":"第1季","2":"第2季","3":"第3季","4":"第4季"},"narrow":{"1":"1","2":"2","3":"3","4":"4"},"wide":{"1":"第1季","2":"第2季","3":"第3季","4":"第4季"}}},"group_symbol":",","days":{"format":{"wide":{"0":"星期一","1":"星期二","2":"星期三","3":"星期四","4":"星期五","5":"星期六","6":"星期日"},"abbreviated":{"0":"週一","1":"週二","2":"週三","3":"週四","4":"週五","5":"週六","6":"週日"},"narrow":{"0":"一","1":"二","2":"三","3":"四","4":"五","5":"六","6":"日"},"short":{"0":"一","1":"二","2":"三","3":"四","4":"五","5":"六","6":"日"}},"stand-alone":{"wide":{"0":"星期一","1":"星期二","2":"星期三","3":"星期四","4":"星期五","5":"星期六","6":"星期日"},"abbreviated":{"0":"週一","1":"週二","2":"週三","3":"週四","4":"週五","5":"週六","6":"週日"},"narrow":{"0":"一","1":"二","2":"三","3":"四","4":"五","5":"六","6":"日"},"short":{"0":"一","1":"二","2":"三","3":"四","4":"五","5":"六","6":"日"}}},"decimal_symbol":".","months":{"format":{"abbreviated":{"1":"1月","2":"2月","3":"3月","4":"4月","5":"5月","6":"6月","7":"7月","8":"8月","9":"9月","10":"10月","11":"11月","12":"12月"},"narrow":{"1":"1","2":"2","3":"3","4":"4","5":"5","6":"6","7":"7","8":"8","9":"9","10":"10","11":"11","12":"12"},"wide":{"1":"1月","2":"2月","3":"3月","4":"4月","5":"5月","6":"6月","7":"7月","8":"8月","9":"9月","10":"10月","11":"11月","12":"12月"}},"stand-alone":{"abbreviated":{"1":"1月","2":"2月","3":"3月","4":"4月","5":"5月","6":"6月","7":"7月","8":"8月","9":"9月","10":"10月","11":"11月","12":"12月"},"narrow":{"1":"1","2":"2","3":"3","4":"4","5":"5","6":"6","7":"7","8":"8","9":"9","10":"10","11":"11","12":"12"},"wide":{"1":"1月","2":"2月","3":"3月","4":"4月","5":"5月","6":"6月","7":"7月","8":"8月","9":"9月","10":"10月","11":"11月","12":"12月"}}},"minus_sign":"-","min_week_days":1,"first_week_day":6,"periods":{"night1":"凌晨","evening1":"晚上","morning2":"上午","afternoon1":"中午","pm":"下午","am":"上午","morning1":"清晨","afternoon2":"下午","midnight":"午夜"},"datetime_formats":{"null":"{1} {0}"},"number_format":"#,##0.###","locale_name":"zh_TW","plus_sign":"+","eras":{"abbreviated":{"0":"西元前","1":"西元"},"narrow":{"0":"西元前","1":"西元"},"wide":{"0":"西元前","1":"西元"}}}
    };

var getLocaleData = function (locale) {
    if (!LOCALES[locale]) {
	    locale = 'en_US';
    }
    return LOCALES[locale];
}

var isValidLocaleFormat = function (locale) {
    // https://www.w3.org/Protocols/rfc2616/rfc2616-sec3.html#sec3.10
    var validLocaleRegex = new RegExp(/^[a-z0-9]{1,8}([-_][a-z0-9]{1,8})*$/i);
    return validLocaleRegex.test(locale);
}

exports.getLocaleData = getLocaleData;
exports.isValidLocaleFormat = isValidLocaleFormat;
