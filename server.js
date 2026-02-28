const express = require('express');
const { ethers } = require('ethers');
const app = express();

app.use(express.json());

// Environment Variables
const PORT = process.env.PORT || 3000;
const SIGNER_KEY = process.env.SIGNER_KEY;

if (!SIGNER_KEY) {
    console.error("CRITICAL ERROR: SIGNER_KEY is not defined in Environment Variables!");
    process.exit(1);
}

// Initialize Wallet
const wallet = new ethers.Wallet(SIGNER_KEY);
const CONTRACT_ADDRESS = "0xB3A59e559B470Ce9Edc1Ccf70B912F8A021a4552";
const CHAIN_ID = 10143;

// Health check endpoint
app.get('/', (req, res) => {
    res.status(200).send('Axil Protocol Signer API is LIVE');
});

// Signing endpoint
app.post('/sign', async (req, res) => {
    try {
        const { merchant, user, agent, amount, salt, intentText } = req.body;

        // Generate packedIntent using Keccak256
        const currentSalt = salt || Math.floor(Math.random() * 1000000);
        const packedIntent = ethers.utils.keccak256(
            ethers.utils.defaultAbiCoder.encode(
                ["uint128", "string"],
                [currentSalt, intentText || "Axil Execution"]
            )
        );

        const deadline = Math.floor(Date.now() / 1000) + 86400; // 24h validity

        const domain = {
            name: "AxilProtocolV1",
            version: "1",
            chainId: CHAIN_ID,
            verifyingContract: CONTRACT_ADDRESS
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
            amount: ethers.utils.parseUnits(amount.toString(), 18),
            deadline,
            salt: currentSalt,
            agent
        };

        // Sign EIP-712 Typed Data
        const signature = await wallet._signTypedData(domain, types, message);

        console.log(Signed intent for user: ${user});

        res.json({
            success: true,
            signature,
            packedIntent,
            deadline,
            salt: currentSalt,
            contract: CONTRACT_ADDRESS
        });

    } catch (error) {
        console.error("Signing Error:", error.message);
        res.status(500).json({ error: error.message });
    }
});

app.listen(PORT, () => {
    console.log(Axil Protocol Signer running on port ${PORT});
    console.log(Admin Wallet: ${wallet.address});
});
