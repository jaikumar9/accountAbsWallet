// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.20;

import {IEntryPoint} from "lib/account-abstraction/contracts/interfaces/IEntryPoint.sol";
import {BaseAccount} from "lib/account-abstraction/contracts/core/BaseAccount.sol";
import {UserOperation} from "lib/account-abstraction/contracts/interfaces/UserOperation.sol";
import {ECDSA} from "lib/openzeppelin-contracts/contracts/utils/cryptography/ECDSA.sol";
import {Initializable} from "lib/openzeppelin-contracts/contracts/proxy/utils/Initializable.sol";
import {UUPSUpgradeable} from "lib/openzeppelin-contracts/contracts/proxy/utils/UUPSUpgradeable.sol";
import {TokenCallbackHandler} from "lib/account-abstraction/contracts/samples/callback/TokenCallbackHandler.sol";

contract Wallet is BaseAccount, Initializable, UUPSUpgradeable, TokenCallbackHandler {

    address public immutable walletFactory;
    IEntryPoint private immutable _entryPoint;

    using ECDSA for bytes32;
    address[] public owners;

    constructor(IEntryPoint anEntryPoint, address ourWalletFactory) {
        _entryPoint = anEntryPoint;
        walletFactory = ourWalletFactory;
    }

    // Events
    event WalletInitialized(IEntryPoint indexed entryPoint, address[] owners);

    function entryPoint() public view override returns (IEntryPoint) {
        return _entryPoint;
    }

    function _validateSignature(UserOperation calldata userOp,bytes32 userOpHash) internal view override returns (uint256) {
        // Convert the userOpHash to an Ethereum Signed Message Hash
        bytes32 hash = userOpHash.toEthSignedMessageHash();
        // Decode the signatures from the userOp and store them in a bytes array in memory
        bytes[] memory signatures = abi.decode(userOp.signature, (bytes[]));

        // Loop through all the owners of the wallet
        for (uint256 i = 0; i < owners.length; i++) {
            // Recover the signer's address from each signature
            // If the recovered address doesn't match the owner's address, return SIG_VALIDATION_FAILED
            if (owners[i] != hash.recover(signatures[i])) {
                return SIG_VALIDATION_FAILED;
            }
        }
        // If all signatures are valid (i.e., they all belong to the owners), return 0
        return 0;
    }

    function initialize(address[] memory initialOwners) public initializer {
    _initialize(initialOwners);
}

function _initialize(address[] memory initialOwners) internal {
    require(initialOwners.length > 0, "no owners");
    owners = initialOwners;
    emit WalletInitialized(_entryPoint, initialOwners);
}

    function _call(address target, uint256 value, bytes memory data) internal {
        (bool success, bytes memory result) = target.call{value: value}(data); //  data = method id for pointing to the method to be called from the target function.
        if (!success) {
            assembly {
                // The assembly code here skips the first 32 bytes of the result, which contains the length of data.
                // It then loads the actual error message using mload and calls revert with this error message.
                revert(add(result, 32), mload(result))
            }
        }
    }

    modifier _requireFromEntryPointOrFactory() {
        require(
            msg.sender == address(_entryPoint) || msg.sender == walletFactory,
            "only entry point or wallet factory can call"
        );
        _;
    }

   function execute(
    address dest,
    uint256 value,
    bytes calldata func
) external _requireFromEntryPointOrFactory {
    _call(dest, value, func);
}

function executeBatch(
    address[] calldata dests,
    uint256[] calldata values,
    bytes[] calldata funcs
) external _requireFromEntryPointOrFactory {
    require(dests.length == funcs.length, "wrong dests lengths");
    require(values.length == funcs.length, "wrong values lengths");
    for (uint256 i = 0; i < dests.length; i++) {
        _call(dests[i], values[i], funcs[i]);
    }
}

function _authorizeUpgrade(address) internal view override _requireFromEntryPointOrFactory {}


// Helper Functions 

function encodeSignatures(bytes[] memory signatures) public pure returns (bytes memory) {
    return abi.encode(signatures);
}

function getDeposit() public view returns (uint256) {
    return entryPoint().balanceOf(address(this));
}

function addDeposit() public payable {
    entryPoint().depositTo{value: msg.value}(address(this));
}
receive() external payable {}


}
