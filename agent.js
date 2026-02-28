const { ethers } = require("ethers");

const RPC = "https://monad-testnet.g.alchemy.com/v2/XhVRkVlT4Bb327xPeIgv7";
const PRIVATE_KEY = "0x298a495a267f351c312e3ad7b633a8bd9d68018fd01734b63b61ed3bb53ed4ee";
const CONTRACT = "0xB3A59e559B470Ce9Edc1Ccf70B912F8A021a4552";

// Адреса
const merchant = "0x8cFBB1eEaF94d5877E21D191cA95A520a8710A21";
const user = "0x8cFBB1eEaF94d5877E21D191cA95A520a8710A21";
const packedIntent = "0x0000000000000000000000000000000100000000000000000000000000000001";
const deadline = Math.floor(Date.now() / 1000) + 3600;
const salt = 12345;
const amount = ethers.utils.parseEther("1");

// ABI контракта
const abi = [
  "function execute(address merchant, address user, bytes32 packedIntent, uint256 deadline, uint128 salt, bytes calldata signature) external payable"
];

async function main() {
  const provider = new ethers.providers.JsonRpcProvider(RPC);
  const wallet = new ethers.Wallet(PRIVATE_KEY, provider);
  const contract = new ethers.Contract(CONTRACT, abi, wallet);

  // === 1. Получаем domain separator ===
  const domain = {
    name: "AxilProtocolV1",
    version: "1",
    chainId: 10143, // chainId Monad testnet
    verifyingContract: CONTRACT
  };

  // === 2. Тип для execute ===
  const types = {
    Execute: [
      { name: "merchant", type: "address" },
      { name: "user", type: "address" },
      { name: "packedIntent", type: "bytes32" },
      { name: "amount", type: "uint128" },
      { name: "deadline", type: "uint256" },
      { name: "salt", type: "uint128" },
      { name: "agent", type: "address" }
    ]
  };

  // === 3. Данные для подписи ===
  const value = {
    merchant,
    user,
    packedIntent,
    amount: ethers.BigNumber.from(amount), // uint128
    deadline,
    salt,
    agent: wallet.address // кто вызывает
  };

  console.log("🔐 Генерирую подпись...");

  // === 4. Подписываем EIP-712 ===
  const signature = await wallet._signTypedData(domain, types, value);

  console.log("✅ Подпись готова:", signature);

  // === 5. Отправляем execute ===
  console.log("📦 Отправляю execute...");

  const tx = await contract.execute(
    merchant,
    user,
    packedIntent,
    deadline,
    salt,
    signature,
    { value: amount }
  );

  console.log("✅ Хэш:", tx.hash);
  await tx.wait();
  console.log("🎯 Транзакция подтверждена!");
}

main().catch(console.error);