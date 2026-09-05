// Explicit matcher registration: on a mapped network drive (F: → \\RunoNAS\home) module
// resolution can yield two chai instances, leaving hardhat-chai-matchers unregistered in
// the one mocha hands us. Requiring the plugin here pins it to this file's chai.
require("@nomicfoundation/hardhat-chai-matchers");
const { expect } = require("chai");
const { ethers } = require("hardhat");

// ───────────────── helpers ─────────────────

function makeRecipient(versionByte = 0x32) {
  // 32-byte addr32: [version_byte | 31 random bytes]
  const rest = ethers.randomBytes(31);
  return ethers.concat([new Uint8Array([versionByte]), rest]);
}

function makeNonce() {
  return ethers.hexlify(ethers.randomBytes(32));
}

async function makeDomain(bridge) {
  const { chainId } = await ethers.provider.getNetwork();
  return {
    name: "MXDBridge",
    version: "3",
    chainId,
    verifyingContract: await bridge.getAddress(),
  };
}

const TYPES = {
  AddOperator: [
    { name: "operator", type: "address" },
    { name: "nonce", type: "bytes32" },
    { name: "deadline", type: "uint256" },
  ],
  RemoveOperator: [
    { name: "operator", type: "address" },
    { name: "nonce", type: "bytes32" },
    { name: "deadline", type: "uint256" },
  ],
  SetThreshold: [
    { name: "threshold", type: "uint256" },
    { name: "nonce", type: "bytes32" },
    { name: "deadline", type: "uint256" },
  ],
  UpdateDailyCap: [
    { name: "baseCap", type: "uint256" },
    { name: "increment", type: "uint256" },
    { name: "nonce", type: "bytes32" },
    { name: "deadline", type: "uint256" },
  ],
  Pause: [
    { name: "nonce", type: "bytes32" },
    { name: "deadline", type: "uint256" },
  ],
  Unpause: [
    { name: "nonce", type: "bytes32" },
    { name: "deadline", type: "uint256" },
  ],
  RecoverToken: [
    { name: "tokenAddr", type: "address" },
    { name: "recipient", type: "address" },
    { name: "amount", type: "uint256" },
    { name: "nonce", type: "bytes32" },
    { name: "deadline", type: "uint256" },
  ],
};

async function sign(signers, domain, primaryType, value) {
  const types = { [primaryType]: TYPES[primaryType] };
  const sigs = [];
  for (const s of signers) {
    sigs.push(await s.signTypedData(domain, types, value));
  }
  return sigs;
}

// ───────────────── fixture ─────────────────

const BASE_CAP = 100_00000000n;          // 100 MXD
const CAP_INCREMENT = 10_00000000n;       // +10/day
const ONE_MXD = 1_00000000n;
const FAR_FUTURE = 10_000_000_000;        // ~ year 2286
const BURN_ADDRESS = "0x000000000000000000000000000000000000dEaD";

// TestBNBMXD mirrors the production token model: fixed supply minted once to the
// deployer, no mint/burn/setBridge — same as the real deployed BNBMXD on BSC mainnet.
// Test balances are seeded with plain transfers; the bridge itself only ever uses
// standard `transferFrom` against the token.
async function deployFixture() {
  const [deployer, user, alice, bob, carol, dave, eve, mallory] = await ethers.getSigners();
  const operators = [alice, bob, carol, dave, eve];

  const TestBNBMXD = await ethers.getContractFactory("TestBNBMXD");
  const token = await TestBNBMXD.deploy(1_000_000n * ONE_MXD);
  await token.waitForDeployment();

  const Bridge = await ethers.getContractFactory("MXDBridgeV3");
  const bridge = await Bridge.deploy(
    await token.getAddress(),
    operators.map((o) => o.address),
    3,                  // 3-of-5
    BASE_CAP,
    CAP_INCREMENT
  );
  await bridge.waitForDeployment();

  // Seed user with a plain transfer from the deployer's fixed supply — the exact
  // mechanism available against the production token.
  await (await token.transfer(user.address, 1000n * ONE_MXD)).wait();

  // User approves the bridge — required by standard ERC20 transferFrom in deposit().
  await (await token.connect(user).approve(await bridge.getAddress(), ethers.MaxUint256)).wait();

  const domain = await makeDomain(bridge);

  return { deployer, user, alice, bob, carol, dave, eve, mallory, operators, token, bridge, domain };
}

// ───────────────── tests ─────────────────

describe("MXDBridgeV3 — deposit", function () {
  it("accepts any non-zero 32-byte recipient (addr32 is raw hash, no version byte)", async function () {
    const { user, bridge } = await deployFixture();
    // Sample first bytes spanning the full 0..255 range to confirm no on-chain version-byte gate.
    for (const firstByte of [0x00, 0x01, 0x32, 0x33, 0x3a, 0x3b, 0x80, 0xff]) {
      const recipient = makeRecipient(firstByte);
      // First byte == 0x00 with all-zero rest would trip the zero-recipient guard, but our
      // helper appends 31 random bytes so the value is non-zero overall.
      await expect(bridge.connect(user).deposit(recipient, ONE_MXD))
        .to.emit(bridge, "Deposit")
        .withArgs(user.address, ethers.hexlify(recipient), ONE_MXD, anyValue(), anyValue());
    }
  });

  it("reverts on zero amount and on the all-zero recipient", async function () {
    const { user, bridge } = await deployFixture();

    await expect(bridge.connect(user).deposit(makeRecipient(0x32), 0n))
      .to.be.revertedWithCustomError(bridge, "ZeroAmount");

    await expect(bridge.connect(user).deposit(ethers.ZeroHash, ONE_MXD))
      .to.be.revertedWithCustomError(bridge, "ZeroAddress");
  });

  it("transfers BNBMXD from sender to BURN_ADDRESS and emits sequential depositIds", async function () {
    const { user, bridge, token } = await deployFixture();
    const userBefore = await token.balanceOf(user.address);
    const burnBefore = await token.balanceOf(BURN_ADDRESS);
    const bridgeBefore = await token.balanceOf(await bridge.getAddress());

    const tx1 = await bridge.connect(user).deposit(makeRecipient(0x32), 5n * ONE_MXD);
    const r1 = await tx1.wait();
    const tx2 = await bridge.connect(user).deposit(makeRecipient(0x32), 3n * ONE_MXD);
    const r2 = await tx2.wait();

    expect(userBefore - (await token.balanceOf(user.address))).to.eq(8n * ONE_MXD);
    expect((await token.balanceOf(BURN_ADDRESS)) - burnBefore).to.eq(8n * ONE_MXD);
    // Bridge itself must never hold any BNBMXD during a normal deposit flow.
    expect(await token.balanceOf(await bridge.getAddress())).to.eq(bridgeBefore);

    const ev1 = r1.logs.find((l) => l.fragment?.name === "Deposit").args;
    const ev2 = r2.logs.find((l) => l.fragment?.name === "Deposit").args;
    expect(ev2.depositId).to.eq(ev1.depositId + 1n);
  });

  it("reverts deposit when user has not approved the bridge", async function () {
    const { user, bridge, token, deployer } = await deployFixture();
    // Reset allowance back to zero for this test
    await (await token.connect(user).approve(await bridge.getAddress(), 0)).wait();

    await expect(bridge.connect(user).deposit(makeRecipient(0x32), ONE_MXD))
      .to.be.revertedWithCustomError(token, "ERC20InsufficientAllowance");
  });

  it("enforces daily cap and rolls over after a day", async function () {
    const { user, bridge } = await deployFixture();
    const cap = await bridge.currentDailyCap();
    expect(cap).to.eq(BASE_CAP);

    // Fill cap exactly
    await bridge.connect(user).deposit(makeRecipient(0x32), cap);

    // One more wei reverts
    await expect(bridge.connect(user).deposit(makeRecipient(0x32), 1n))
      .to.be.revertedWithCustomError(bridge, "DailyCapExceeded");

    // Advance 1 day, cap = BASE + 1 * INC
    await ethers.provider.send("evm_increaseTime", [86400]);
    await ethers.provider.send("evm_mine", []);
    const newCap = await bridge.currentDailyCap();
    expect(newCap).to.eq(BASE_CAP + CAP_INCREMENT);

    // Daily total reset on the next deposit
    await bridge.connect(user).deposit(makeRecipient(0x32), newCap);
    expect(await bridge.dailyDepositUsed()).to.eq(newCap);
  });
});

describe("MXDBridgeV3 — K-of-N admin", function () {
  it("addOperator with 3 valid sigs adds a new operator", async function () {
    const { operators, mallory, bridge, domain } = await deployFixture();
    const value = { operator: mallory.address, nonce: makeNonce(), deadline: FAR_FUTURE };
    const sigs = await sign(operators.slice(0, 3), domain, "AddOperator", value);

    await expect(bridge.addOperator(value.operator, value.nonce, value.deadline, sigs))
      .to.emit(bridge, "OperatorAdded")
      .withArgs(mallory.address, value.nonce);

    expect(await bridge.isOperator(mallory.address)).to.eq(true);
    expect(await bridge.operatorCount()).to.eq(6n);
  });

  it("rejects insufficient signatures", async function () {
    const { operators, mallory, bridge, domain } = await deployFixture();
    const value = { operator: mallory.address, nonce: makeNonce(), deadline: FAR_FUTURE };
    const sigs = await sign(operators.slice(0, 2), domain, "AddOperator", value);

    await expect(bridge.addOperator(value.operator, value.nonce, value.deadline, sigs))
      .to.be.revertedWithCustomError(bridge, "InsufficientSignatures");
  });

  it("rejects duplicate signer even if 3 sigs supplied", async function () {
    const { operators, mallory, bridge, domain } = await deployFixture();
    const value = { operator: mallory.address, nonce: makeNonce(), deadline: FAR_FUTURE };
    const types = { AddOperator: TYPES.AddOperator };
    const sigA = await operators[0].signTypedData(domain, types, value);
    const sigB = await operators[1].signTypedData(domain, types, value);
    // duplicate sigA
    const sigs = [sigA, sigB, sigA];

    await expect(bridge.addOperator(value.operator, value.nonce, value.deadline, sigs))
      .to.be.revertedWithCustomError(bridge, "DuplicateSigner");
  });

  it("rejects signature from non-operator", async function () {
    const { operators, mallory, bridge, domain } = await deployFixture();
    const value = { operator: mallory.address, nonce: makeNonce(), deadline: FAR_FUTURE };
    const goodSigs = await sign(operators.slice(0, 2), domain, "AddOperator", value);
    // mallory isn't an operator yet
    const malSig = await mallory.signTypedData(domain, { AddOperator: TYPES.AddOperator }, value);

    await expect(bridge.addOperator(value.operator, value.nonce, value.deadline, [...goodSigs, malSig]))
      .to.be.revertedWithCustomError(bridge, "InvalidSignature");
  });

  it("rejects expired deadline and replayed nonce", async function () {
    const { operators, mallory, bridge, domain } = await deployFixture();

    // Expired deadline
    const block = await ethers.provider.getBlock("latest");
    const pastValue = { operator: mallory.address, nonce: makeNonce(), deadline: block.timestamp - 1 };
    const pastSigs = await sign(operators.slice(0, 3), domain, "AddOperator", pastValue);
    await expect(bridge.addOperator(pastValue.operator, pastValue.nonce, pastValue.deadline, pastSigs))
      .to.be.revertedWithCustomError(bridge, "DeadlineExpired");

    // First good action
    const v = { operator: mallory.address, nonce: makeNonce(), deadline: FAR_FUTURE };
    const sigs = await sign(operators.slice(0, 3), domain, "AddOperator", v);
    await bridge.addOperator(v.operator, v.nonce, v.deadline, sigs);

    // Same nonce reused — rejected. Need to make mallory not-already-an-operator,
    // so we test by trying RemoveOperator with the same nonce.
    const rv = { operator: mallory.address, nonce: v.nonce, deadline: FAR_FUTURE };
    const rsigs = await sign(operators.slice(0, 3), domain, "RemoveOperator", rv);
    await expect(bridge.removeOperator(rv.operator, rv.nonce, rv.deadline, rsigs))
      .to.be.revertedWithCustomError(bridge, "NonceAlreadyUsed");
  });

  it("removeOperator clamps threshold when too few operators remain", async function () {
    const { operators, bridge, domain } = await deployFixture();
    // Start: 5 ops, threshold 3. Remove 3 ops → 2 ops left, threshold should clamp to 2.
    for (let i = 4; i >= 2; i--) {
      const v = { operator: operators[i].address, nonce: makeNonce(), deadline: FAR_FUTURE };
      const sigs = await sign(operators.slice(0, 3), domain, "RemoveOperator", v);
      await bridge.removeOperator(v.operator, v.nonce, v.deadline, sigs);
    }
    expect(await bridge.operatorCount()).to.eq(2n);
    expect(await bridge.threshold()).to.eq(2n);
  });

  it("cannot remove last operator", async function () {
    const { operators, bridge, domain } = await deployFixture();
    // Drop from 5 → 1 by removing operators[4], [3], [2], [1] in order.
    // At each step the active set is operators[0..i], so we pick first `threshold` of those.
    for (let i = 4; i >= 1; i--) {
      const v = { operator: operators[i].address, nonce: makeNonce(), deadline: FAR_FUTURE };
      const t = await bridge.threshold();
      const active = operators.slice(0, i + 1);
      const signers = active.slice(0, Number(t));
      const sigs = await sign(signers, domain, "RemoveOperator", v);
      await bridge.removeOperator(v.operator, v.nonce, v.deadline, sigs);
    }
    expect(await bridge.operatorCount()).to.eq(1n);
    expect(await bridge.threshold()).to.eq(1n);

    const v = { operator: operators[0].address, nonce: makeNonce(), deadline: FAR_FUTURE };
    const sigs = await sign([operators[0]], domain, "RemoveOperator", v);
    await expect(bridge.removeOperator(v.operator, v.nonce, v.deadline, sigs))
      .to.be.revertedWithCustomError(bridge, "CannotRemoveLastOperator");
  });

  it("setThreshold validates bounds", async function () {
    const { operators, bridge, domain } = await deployFixture();

    const bad0 = { threshold: 0n, nonce: makeNonce(), deadline: FAR_FUTURE };
    const sigs0 = await sign(operators.slice(0, 3), domain, "SetThreshold", bad0);
    await expect(bridge.setThreshold(bad0.threshold, bad0.nonce, bad0.deadline, sigs0))
      .to.be.revertedWithCustomError(bridge, "InvalidThreshold");

    const bad6 = { threshold: 6n, nonce: makeNonce(), deadline: FAR_FUTURE };
    const sigs6 = await sign(operators.slice(0, 3), domain, "SetThreshold", bad6);
    await expect(bridge.setThreshold(bad6.threshold, bad6.nonce, bad6.deadline, sigs6))
      .to.be.revertedWithCustomError(bridge, "InvalidThreshold");

    const good = { threshold: 4n, nonce: makeNonce(), deadline: FAR_FUTURE };
    const sigsG = await sign(operators.slice(0, 3), domain, "SetThreshold", good);
    await bridge.setThreshold(good.threshold, good.nonce, good.deadline, sigsG);
    expect(await bridge.threshold()).to.eq(4n);
  });

  it("updateDailyCap takes effect immediately", async function () {
    const { operators, bridge, domain } = await deployFixture();
    const newBase = 500_00000000n;
    const newInc = 50_00000000n;
    const v = { baseCap: newBase, increment: newInc, nonce: makeNonce(), deadline: FAR_FUTURE };
    const sigs = await sign(operators.slice(0, 3), domain, "UpdateDailyCap", v);

    await bridge.updateDailyCap(v.baseCap, v.increment, v.nonce, v.deadline, sigs);
    expect(await bridge.currentDailyCap()).to.eq(newBase);
  });

  it("pause blocks deposit; unpause restores it", async function () {
    const { operators, user, bridge, domain } = await deployFixture();

    const pv = { nonce: makeNonce(), deadline: FAR_FUTURE };
    const psigs = await sign(operators.slice(0, 3), domain, "Pause", pv);
    await bridge.pause(pv.nonce, pv.deadline, psigs);

    await expect(bridge.connect(user).deposit(makeRecipient(0x32), ONE_MXD))
      .to.be.revertedWithCustomError(bridge, "BridgePaused");

    const uv = { nonce: makeNonce(), deadline: FAR_FUTURE };
    const usigs = await sign(operators.slice(0, 3), domain, "Unpause", uv);
    await bridge.unpause(uv.nonce, uv.deadline, usigs);

    await expect(bridge.connect(user).deposit(makeRecipient(0x32), ONE_MXD)).to.emit(bridge, "Deposit");
  });

  it("recoverToken cannot recover BNBMXD itself", async function () {
    const { operators, token, bridge, domain, alice } = await deployFixture();
    const v = {
      tokenAddr: await token.getAddress(),
      recipient: alice.address,
      amount: 1n,
      nonce: makeNonce(),
      deadline: FAR_FUTURE,
    };
    const sigs = await sign(operators.slice(0, 3), domain, "RecoverToken", v);
    await expect(bridge.recoverToken(v.tokenAddr, v.recipient, v.amount, v.nonce, v.deadline, sigs))
      .to.be.revertedWithCustomError(bridge, "CannotRecoverBridgeToken");
  });

  it("recoverToken works for unrelated ERC20", async function () {
    const { operators, bridge, domain, alice, deployer } = await deployFixture();

    // Deploy a foreign ERC20 and send some to the bridge "by accident".
    const Foreign = await ethers.getContractFactory("TestBNBMXD");
    const foreign = await Foreign.deploy(100n);
    await foreign.waitForDeployment();
    await foreign.transfer(await bridge.getAddress(), 100n);

    const v = {
      tokenAddr: await foreign.getAddress(),
      recipient: alice.address,
      amount: 100n,
      nonce: makeNonce(),
      deadline: FAR_FUTURE,
    };
    const sigs = await sign(operators.slice(0, 3), domain, "RecoverToken", v);
    await bridge.recoverToken(v.tokenAddr, v.recipient, v.amount, v.nonce, v.deadline, sigs);
    expect(await foreign.balanceOf(alice.address)).to.eq(100n);
  });
});

describe("MXDBridgeV3 — constructor validation", function () {
  it("rejects zero token, empty operators, invalid threshold", async function () {
    const [, alice, bob] = await ethers.getSigners();
    const TestBNBMXD = await ethers.getContractFactory("TestBNBMXD");
    const token = await TestBNBMXD.deploy(1_000_000n * ONE_MXD);
    await token.waitForDeployment();
    const tokenAddr = await token.getAddress();

    const Bridge = await ethers.getContractFactory("MXDBridgeV3");

    await expect(Bridge.deploy(ethers.ZeroAddress, [alice.address], 1, BASE_CAP, CAP_INCREMENT))
      .to.be.revertedWithCustomError(Bridge, "ZeroAddress");

    await expect(Bridge.deploy(tokenAddr, [], 1, BASE_CAP, CAP_INCREMENT))
      .to.be.revertedWithCustomError(Bridge, "EmptyOperatorSet");

    await expect(Bridge.deploy(tokenAddr, [alice.address], 0, BASE_CAP, CAP_INCREMENT))
      .to.be.revertedWithCustomError(Bridge, "InvalidThreshold");

    await expect(Bridge.deploy(tokenAddr, [alice.address], 2, BASE_CAP, CAP_INCREMENT))
      .to.be.revertedWithCustomError(Bridge, "InvalidThreshold");

    await expect(Bridge.deploy(tokenAddr, [alice.address, alice.address], 1, BASE_CAP, CAP_INCREMENT))
      .to.be.revertedWithCustomError(Bridge, "AlreadyOperator");

    await expect(Bridge.deploy(tokenAddr, [alice.address, ethers.ZeroAddress], 1, BASE_CAP, CAP_INCREMENT))
      .to.be.revertedWithCustomError(Bridge, "ZeroAddress");
  });
});

// Tiny helper: chai's anyValue isn't auto-imported in older hardhat-toolbox versions.
function anyValue() {
  return (v) => true;
}
