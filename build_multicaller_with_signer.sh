mkdir .tmp > /dev/null 2>&1;

forge fmt;

cp src/MulticallerWithSigner.sol .tmp;

echo 'const fs = require("fs"), rfs = s => fs.readFileSync(s, { encoding: "utf8", flag: "r" });
const p = ".tmp/MulticallerWithSigner.sol";
fs.writeFileSync(
    p, 
    rfs(p).replace(/import\s*?\"\.\/utils/, "import \".")
)' > .tmp/replace_imports.js;
node .tmp/replace_imports.js;

rm .tmp/foundry.toml > /dev/null 2>&1;

forge build --out="out" --root=".tmp" --contracts="." --via-ir --optimize --optimizer-runs=200 --use=0.8.18;

mkdir multicaller_with_signer > /dev/null 2>&1;

echo 'const fs = require("fs"), rfs = s => fs.readFileSync(s, { encoding: "utf8", flag: "r" });
fs.writeFileSync(
    "multicaller_with_signer/initcode.txt", 
    JSON.parse(rfs(".tmp/out/MulticallerWithSigner.sol/MulticallerWithSigner.json"))["bytecode"]["object"].slice(2)
)' > .tmp/extract_initcode.js;
node .tmp/extract_initcode.js;

echo 'const fs = require("fs"), rfs = s => fs.readFileSync(s, { encoding: "utf8", flag: "r" });
fs.writeFileSync(
    "multicaller_with_signer/input.json", 
    JSON.stringify({
        "language": "Solidity",
        "sources": {
            "MulticallerWithSigner.sol": {
                "content": rfs(".tmp/MulticallerWithSigner.sol")
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
    "multicaller_with_signer/initcodehash.txt", 
    require("@ethersproject/keccak256").keccak256("0x" + rfs("multicaller_with_signer/initcode.txt"))
)' > .tmp/generate_initcodehash.js;
node .tmp/generate_initcodehash.js;

rm .tmp/*.sol .tmp/*.js > /dev/null 2>&1;

cat multicaller_with_signer/initcodehash.txt; echo;
cat multicaller_with_signer/initcode.txt; echo;
