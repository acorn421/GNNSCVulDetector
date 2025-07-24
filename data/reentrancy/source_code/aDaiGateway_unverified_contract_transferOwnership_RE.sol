/*
 * ===== SmartInject Injection Details =====
 * Function      : transferOwnership
 * Vulnerability : Reentrancy
 * Status        : Not Detected
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : False
 * Relevant      : 0 findings
 * Total Found   : 0 issues
 * Retry Count   : 0
 *
 * === Description ===
 * This modification introduces a stateful, multi-transaction reentrancy vulnerability by:
 * 
 * 1. **Added Persistent State**: A `pendingOwnershipTransfers` mapping tracks ownership transfer status between transactions
 * 2. **External Call Before State Update**: Added a callback to the new owner address before updating the owner state variable
 * 3. **Reentrancy Window**: The owner variable is updated after the external call, creating a window where the old owner is still active during the callback
 * 
 * **Multi-Transaction Exploitation Scenario:**
 * 
 * **Transaction 1 (Setup)**: 
 * - Attacker deploys a malicious contract at `newOwner` address
 * - Malicious contract implements `onOwnershipTransferred()` function that re-enters the contract
 * 
 * **Transaction 2 (Initial Transfer)**:
 * - Current owner calls `transferOwnership(attackerContract)`
 * - `pendingOwnershipTransfers[attackerContract] = true`
 * - External call to `attackerContract.onOwnershipTransferred()`
 * - During callback, attacker can call other privileged functions while `owner` is still the old owner
 * - Attacker can also call `transferOwnership` again to different addresses
 * 
 * **Transaction 3+ (Exploitation)**:
 * - The attacker can exploit the inconsistent state where `pendingOwnershipTransfers` shows transfer in progress but `owner` hasn't been updated
 * - Multiple reentrant calls can manipulate contract state before ownership is finalized
 * - The attacker can potentially drain funds via `makeprofit()` or manipulate other owner-only functions
 * 
 * **Why Multi-Transaction is Required:**
 * - The attacker must first deploy a malicious contract with the callback function (Transaction 1)
 * - The actual vulnerability is triggered when the legitimate owner initiates the transfer (Transaction 2)
 * - The exploit requires the external call to re-enter the contract during the callback, which happens within the transfer transaction but enables further transactions
 * - The persistent `pendingOwnershipTransfers` state allows tracking transfer status across transactions
 * 
 * This creates a realistic reentrancy vulnerability that requires careful orchestration across multiple transactions and exploits the state inconsistency window.
 */
pragma solidity ^0.4.24;

contract Ownable {
    address public owner;

    event OwnershipTransferred(
        address indexed previousOwner,
        address indexed newOwner
    );
    /**
     * @dev The Ownable constructor sets the original `owner` of the contract to the sender
     * account.
     */
    constructor() public {
        owner = msg.sender;
    }
    /**
     * @dev Throws if called by any account other than the owner.
     */
    modifier onlyOwner() {
        require(msg.sender == owner);
        _;
    }
    /**
    * @dev Allows the current owner to transfer control of the contract to a newOwner.
    * @param newOwner The address to transfer ownership to.
    */
    // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
    mapping(address => bool) public pendingOwnershipTransfers;

    function transferOwnership(address newOwner) public onlyOwner {
        require(newOwner != address(0));
        // Mark as pending transfer for multi-transaction security
        pendingOwnershipTransfers[newOwner] = true;

        emit OwnershipTransferred(owner, newOwner);

        // Notify new owner with callback (vulnerable external call)
        uint size;
        assembly { size := extcodesize(newOwner) } // Check if newOwner is a contract
        if (size > 0) {
            (bool success, ) = newOwner.call(
                abi.encodeWithSignature("onOwnershipTransferred(address)", owner)
            );
            // Continue regardless of callback success
        }

        // State update after external call - creates reentrancy window
        owner = newOwner;
        pendingOwnershipTransfers[newOwner] = false;
// ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
    }
}

contract Erc20 {
    function balanceOf(address _owner) public view returns (uint256);
    function transfer(address _to, uint256 _value) public returns (bool);
    function approve(address _spender, uint256 _value) public returns (bool);
}

contract Exchange {
    function ethToTokenSwapInput(uint256 min_tokens, uint256 deadline)
        public
        payable
        returns (uint256);
}

contract LendingPool {
    function deposit( address _reserve, uint256 _amount, uint16 _referralCode) external payable;
}

contract aDaiGateway is Ownable {
    Exchange constant DaiEx = Exchange(0x2a1530C4C41db0B0b2bB646CB5Eb1A67b7158667);
    LendingPool constant lendingPool = LendingPool(0x398eC7346DcD622eDc5ae82352F02bE94C62d119);

    Erc20 constant  dai = Erc20(0x6B175474E89094C44Da98b954EedeAC495271d0F);
    Erc20 constant aDai = Erc20(0xfC1E690f61EFd961294b3e1Ce3313fBD8aa4f85d);

    uint16 constant referral = 47;

    constructor() public {
        dai.approve(0x3dfd23A6c5E8BbcFc9581d2E864a68feb6a076d3, uint256(-1)); //lendingPoolCore
    }

    function() external payable {
        etherToaDai(msg.sender);
    }

    function etherToaDai(address to)
        public
        payable
        returns (uint256 outAmount)
    {
        uint256 amount = DaiEx.ethToTokenSwapInput.value(
            (msg.value * 995) / 1000
        )(1, now);
        lendingPool.deposit(address(dai), amount, referral);
        outAmount = aDai.balanceOf(address(this));
        aDai.transfer(to, outAmount);
    }

    function makeprofit() public {
        owner.transfer(address(this).balance);
    }

}
