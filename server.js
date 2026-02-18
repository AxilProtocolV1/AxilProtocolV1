const express = require('express');
const { ethers } = require('ethers');
const app = express();
app.use(express.json());

const PORT = process.env.PORT || 3000;
const SIGNER_KEY = process.env.SIGNER_KEY;
const wallet = new ethers.Wallet(SIGNER_KEY);

const CONTRACT = "0xB3A59e559B470Ce9Edc1Ccf70B912F8A021a4552";
const CHAIN_ID = 10143;

// Health check
app.get('/', (req, res) => {
    res.send('Axil Protocol Signer API is running');
});

// Signing endpoint
app.post('/sign', async (req, res) => {
    try {
        const { merchant, user, agent, amount, salt, intentText } = req.body;

        const packedIntent = ethers.utils.keccak256(
            ethers.utils.defaultAbiCoder.encode(
                ["uint128", "string"],
                [salt || Math.floor(Math.random() * 1000000), intentText]
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
            salt: salt || Math.floor(Math.random() * 1000000),
            agent
        };

        const signature = await wallet._signTypedData(domain, types, message);

        res.json({
            success: true,
            signature,
            packedIntent,
            deadline,
            salt: message.salt
        });

    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

app.listen(PORT, () => {
    console.log(Server running on port ${PORT});
});
