mkdir .tmp > /dev/null 2>&1;

forge fmt;

cp src/Multicaller.sol .tmp;

echo 'const fs = require("fs"), rfs = s => fs.readFileSync(s, { encoding: "utf8", flag: "r" });
const p = ".tmp/Multicaller.sol";
fs.writeFileSync(
    p, 
    rfs(p).replace(/import\s*?\"\.\/utils/, "import \".")
)' > .tmp/replace_imports.js;
node .tmp/replace_imports.js;

rm .tmp/foundry.toml > /dev/null 2>&1;

forge build --out="out" --root=".tmp" --contracts="." --via-ir --optimize --optimizer-runs=200 --use=0.8.18;

mkdir multicaller > /dev/null 2>&1;

echo 'const fs = require("fs"), rfs = s => fs.readFileSync(s, { encoding: "utf8", flag: "r" });
fs.writeFileSync(
    "multicaller/initcode.txt", 
    JSON.parse(rfs(".tmp/out/Multicaller.sol/Multicaller.json"))["bytecode"]["object"].slice(2)
)' > .tmp/extract_initcode.js;
node .tmp/extract_initcode.js;

echo 'const fs = require("fs"), rfs = s => fs.readFileSync(s, { encoding: "utf8", flag: "r" });
fs.writeFileSync(
    "multicaller/input.json", 
    JSON.stringify({
        "language": "Solidity",
        "sources": {
            "Multicaller.sol": {
                "content": rfs(".tmp/Multicaller.sol")
            }
        },
        "settings": {
            "optimizer": { "enabled": true, "runs": 200 },
            "viaIR": true,
            "outputSelection": { "*": { "*": [ "evm.bytecode", "evm.deployedBytecode", "abi" ] } }
        }
    })
)' > .tmp/generate_input_json.js;
node .tmp/generate_input_json.js;

echo '{ "devDependencies": { "@ethersproject/keccak256": "5.7.0" } }' > .tmp/package.json;

if [ ! -f .tmp/package-lock.json ]; then cd .tmp; npm install; cd ..; fi

echo 'const fs = require("fs"), rfs = s => fs.readFileSync(s, { encoding: "utf8", flag: "r" });
fs.writeFileSync(
    "multicaller/initcodehash.txt", 
    require("@ethersproject/keccak256").keccak256("0x" + rfs("multicaller/initcode.txt"))
)' > .tmp/generate_initcodehash.js;
node .tmp/generate_initcodehash.js;

rm .tmp/*.sol .tmp/*.js > /dev/null 2>&1;

cat multicaller/initcodehash.txt; echo;
cat multicaller/initcode.txt; echo;
