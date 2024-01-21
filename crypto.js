;((lib,env,main,sum,enc,dec)=>{/*module:@niknils/crypto:2024.1.21,src:Wrepo""*/env={
        declare : null, //preprocessing standard;
        engine  : null
    }; //engine detect:
    try{if(process.versions.node.match(/^(0|[1-9][0-9]{0,})(\.(0|[1-9][0-9]{0,})){0,}$/)){env.engine='node'}else{throw('next')}}catch{};
    try{if(window.navigator.userAgent.match(/^[^\r\n]{1,}$/)){env.engine='brow'}else{throw('next')}}catch{};
    try{if(Deno.version.deno.match(/^(0|[1-9][0-9]{0,})(\.(0|[1-9][0-9]{0,})){0,}$/)){env.engine='deno'}else{throw('next')}}catch{};
    //wrap function
    var wrap=function(f,prefix=[],postfix=[]) {
        if (!Array.isArray(prefix)) prefix=[prefix]; prefix.eval=[];
        if (!Array.isArray(postfix)) postfix=[postfix]; postfix.eval=[];
        for (var fix in prefix) {
            if (parseInt(fix)==fix&&fix>-1) prefix.eval.push(`prefix[${fix}]`);
        }
        for (var fix in postfix) {
            if (parseInt(fix)==fix&&fix>-1) postfix.eval.push(`postfix[${fix}]`);
        }
        return function $wrap(args) {
            args=Object.assign([args].concat(Array.from(arguments).slice(1,)).slice(0,arguments.length),
            {
                eval:[]
            });
            for (var arg in args) {
                if (parseInt(arg)==arg&&arg>-1) args.eval.push(`args[${arg}]`);
            }
            if (prefix.eval.length!=0) args.eval=prefix.eval.concat(args);
            if (postfix.eval.length!=0) args.eval=args.eval.concat(postfix.eval);
            var r=f(eval(`${args.eval.join(',')}`));
            return r; //throw^ protect
        }
    }
    //hash
    var sum=((sum)=>{
        function sum(data,algorithm='sha256') {
            if (arguments.length==0) {
                throw(`(ferr:crypto:hash) miss any params; usage:\n`+sum.toString().replace(/^[ ]{8}/gm,''));
            } else if (arguments.length>2) {
                throw(`(ferr:crypto:hash) a lot of options`);
            } else {
                if (typeof data!='string'||typeof algorithm!='string') {
                    throw(`(ferr:crypto:hash) invalid options`);
                } else {
                    try{data=data.toString()}catch{};try{algorithm=algorithm.toString()}catch{};
                    try {
                        if (require('node:crypto').createHash(algorithm).update('test', 'utf8').digest('hex')=='') throw(`->`);
                    } catch {
                        throw(`(ferr:crypto:hash) unknown algorithm`);
                    }
                    return require('node:crypto').createHash(algorithm).update(data).digest('hex');
                }
            }
        }
        for (var algorithm of require('crypto').getHashes()) {
            eval(`sum=Object.assign(sum,{'${algorithm}': wrap(sum, [], algorithm)})`);
        }
        return sum;
    })();
    //crypt
    var enc=((enc)=>{
        function enc(algorithm, data, key=null, iv=null) {
            if (arguments.length==0) {
                throw(`(ferr:crypto/enc) miss params`);
            } else if (arguments.length>4) {
                throw(`(ferr:crypto/enc) a lot of options`); //reserved; arguments todo
            }
            if (!algorithm instanceof String) {
                throw(`(ferr:crypto/enc) invalid usage`);
            } else {
                if (typeof algorithm.encrypt=='string'&&Array.isArray(algorithm.decrypt)) {
                    [algorithm,data,key,iv]=[algorithm.encrypt,algorithm.toString()].concat(algorithm.decrypt);
                } else {
                    if (arguments.length==1) {
                        [algorithm,data]=['base64',algorithm];
                    } else {
                        if (typeof data!='string') {
                            throw(`(ferr:crypto/enc) invalid usage`);
                        }
                    }
                }
            }
            if (algorithm=='base64') {
                data=Buffer.from(data, 'binary').toString('base64');
            } else {
                if (!require('crypto').getCiphers().includes(algorithm)) {
                    throw(`(ferr:crypto/enc) unsupported algorithm`);
                }

                if (key==null) key=32;
                if (typeof key=='number') key=require('crypto').randomBytes(key);
                if (typeof key!='object') throw(`(ferr:crypto/enc) key: invalid type`);

                if (iv==null) iv=16;
                if (typeof iv=='number') iv=require('crypto').randomBytes(iv);
                if (typeof iv!='object') throw(`(ferr:crypto/enc) iv: invalid type`);

                //in review
                var crypt = require('crypto').createCipheriv(algorithm, Buffer.from(key), iv);
                data = Object.assign(Buffer.concat([crypt.update(data), crypt.final()]).toString('base64'),
                {
                   encrypt: algorithm,
                   decrypt:
                   [
                        key,
                        iv
                   ],
                });
            }
            return Object.assign(data,
            {
               then:function(f) {
                   return f(data, {algorithm:algorithm, key:key, iv:iv});
               }
            });
        }
        for (var algorithm of require('crypto').getCiphers()) {
            eval(`enc=Object.assign(enc,{'${algorithm}': wrap(enc, [], algorithm)})`);
        }
        return enc;
    })();
    dec=((dec)=>{
        function dec(algorithm, data, key, iv) {
            if (arguments.length==0) {
                throw(`(ferr:crypto/dec) miss params`);
            } else if (arguments.length>4) {
                throw(`(ferr:crypto/dec) a lot of options`);
            }
            if (!algorithm instanceof String) {
                throw(`(ferr:crypto/dec) invalid usage`);
            } else {
                if (typeof algorithm.encrypt=='string'&&Array.isArray(algorithm.decrypt)) {
                    [algorithm,data,key,iv]=[algorithm.encrypt,algorithm.toString()].concat(algorithm.decrypt);
                } else {
                    if (arguments.length==1) {
                        [algorithm,data]=['base64',algorithm];
                    } else {
                        if (typeof data!='string') {
                            throw(`(ferr:crypto/enc) invalid usage`);
                        }
                    }
                }
            }
            if (algorithm=='base64') {
                data=Buffer.from(data, 'base64').toString();
            } else {
                if (!require('crypto').getCiphers().includes(algorithm)) {
                    throw(`(ferr:crypto/enc) unsupported algorithm`);
                }
                if (typeof key!='object') throw(`(ferr:crypto/enc) key: invalid type`);
                if (typeof iv!='object') throw(`(ferr:crypto/enc) iv: invalid type`);
                [data, iv] = [Buffer.from(data, 'base64'), Buffer.from(iv, 'hex')];

                var crypt = require('node:crypto').createDecipheriv('aes-256-cbc', Buffer.from(key), iv);
                data=Buffer.concat([crypt.update(data), crypt.final()]).toString();
            }
            return Object.assign(data,
            {
                then:function(f) {
                   return f(data, {algorithm:algorithm, key:key, iv:iv});
                }
            });
        }
        for (var algorithm of require('crypto').getCiphers()) {
            eval(`dec=Object.assign(dec,{'${algorithm}': wrap(dec, [], algorithm)})`);
        }
        return dec;
    })();
/*exports--*/
    main=Object.assign(lib,
    {
        sum : sum,
        enc : enc,
        dec : dec
    });
/*-exports-*/
    if (env.engine=='node') eval(`module.exports=main`);
/*--exports*/
})({lib:(()=>{
    return {
        name     : '@niknils/crypto',
        ver      : '2024.1.21',
        contribs : 'slnknrr@noreply.codeberg.org',
        licenses : 'MIT',
        engines  : 'node'
    }
})()});
