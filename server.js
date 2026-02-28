const express = require('express');
const { ethers } = require('ethers');
const app = express();
app.use(express.json());

const PORT = process.env.PORT || 3000;
const SIGNER_KEY = process.env.SIGNER_KEY;
const ALCHEMY_RPC_URL = process.env.ALCHEMY_RPC_URL;

// High-speed provider connection via Alchemy
const provider = new ethers.providers.JsonRpcProvider(ALCHEMY_RPC_URL);
const wallet = new ethers.Wallet(SIGNER_KEY, provider);

const CONTRACT = "0xB3A59e559B470Ce9Edc1Ccf70B912F8A021a4552";
const CHAIN_ID = 10143;

app.get('/', (req, res) => {
    res.send('Axil Protocol Signer API with Alchemy Speed is running');
});

app.post('/sign', async (req, res) => {
    try {
        const { merchant, user, agent, amount, salt, intentText } = req.body;

        const currentSalt = salt || Math.floor(Math.random() * 1000000);
        const packedIntent = ethers.utils.keccak256(
            ethers.utils.defaultAbiCoder.encode(
                ["uint128", "string"],
                [currentSalt, intentText || ""]
            )
        );

        const deadline = Math.floor(Date.now() / 1000) + 86400;

        const domain = {
            name: "AxilProtocolV1",
            version: "1",
            chainId: CHAIN_ID,
            verifyingContract: CONTRACT
        };

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

        const message = {
            merchant,
            user,
            packedIntent,
            amount: ethers.utils.parseEther(amount.toString()),
            deadline,
            salt: currentSalt,
            agent
        };

        const signature = await wallet._signTypedData(domain, types, message);

        console.log(Intent signed for: ${user} | Salt: ${currentSalt});

        res.json({
            success: true,
            signature,
            packedIntent,
            deadline,
            salt: currentSalt
        });

    } catch (error) {
        console.error("Signing Error:", error.message);
        res.status(500).json({ error: error.message });
    }
});

app.listen(PORT, () => {
    console.log(Server running on port ${PORT} with Alchemy connection);
    console.log(Signer Address: ${wallet.address});
});
