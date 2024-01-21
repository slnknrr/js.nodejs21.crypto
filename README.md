# Example

```JavaScript
var { enc, dec, sum } = require(`${__dirname}/crypto.js`);

var message=`
"Your Truth Can Be Changed Simply By The Way You Accept It. That's How Fragile The Truth For A Human Is."
- "Neon Genesis Evangelion", Kozo Fuyutsuki;
`;
var signature=sum(message);
var algorithm='aes-256-cbc';

if (enc(algorithm, message).then((data)=>{
    return dec(data).then((data)=>{
        return sum(message)==signature;
    })
})) {
    console.log(`work`);
} else {
    console.log(`don't work`);
}
```
