/*
 * ===== SmartInject Injection Details =====
 * Function      : freeze
 * Vulnerability : Reentrancy
 * Status        : Verified
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : True
 * Relevant      : 3 findings
 * Total Found   : 3 issues
 * Retry Count   : 0
 *
 * === Detected Issues ===
 * 1. reentrancy-no-eth (SWC-107)
 * 2. reentrancy-benign (SWC-107)
 * 3. reentrancy-events (SWC-107)
 *
 * === Description ===
 * Introduced a stateful, multi-transaction reentrancy vulnerability through a batched freeze processing system with external notifications. The vulnerability requires multiple transactions to accumulate pending freezes before processing, and the external call to rewardContract.notifyFreeze() occurs before state finalization, creating a reentrancy window.
 * 
 * **Key Changes Made:**
 * 
 * 1. **Added State Accumulation**: Introduced `pendingFreezes` mapping to accumulate freeze requests across multiple transactions
 * 2. **External Call Integration**: Added realistic external call to `rewardContract.notifyFreeze()` before state updates
 * 3. **Batch Processing Logic**: Freezes are only processed when `pendingFreezes[msg.sender] >= processingThreshold`
 * 4. **Vulnerable State Management**: The external call happens before the final state updates, creating reentrancy opportunity
 * 
 * **Multi-Transaction Exploitation Process:**
 * 
 * **Transaction 1-N (Accumulation Phase):**
 * - User calls freeze() multiple times with small amounts
 * - Each call adds to pendingFreezes[msg.sender] 
 * - External notification calls occur but balanceOf/freezeOf remain unchanged
 * - No actual freezing happens until threshold is reached
 * 
 * **Transaction N+1 (Exploitation Transaction):**
 * - User calls freeze() with amount that pushes pendingFreezes >= processingThreshold
 * - External call to rewardContract.notifyFreeze() executes first
 * - During this external call, attacker can re-enter freeze() function
 * - The re-entrant call sees the accumulated pendingFreezes but balanceOf hasn't been updated yet
 * - Attacker can manipulate the state during the reentrancy window
 * 
 * **Why Multi-Transaction Required:**
 * 
 * 1. **State Accumulation Dependency**: The vulnerability only triggers when accumulated pendingFreezes reach the threshold, requiring multiple prior transactions
 * 2. **Temporal Attack Vector**: The attack exploits the time window between external notification and state finalization, which requires the accumulated state from previous transactions
 * 3. **Batch Processing Logic**: The vulnerable code path (with external call) only executes after multiple freeze operations have been accumulated
 * 
 * **Realistic Attack Scenario:**
 * - Attacker makes multiple small freeze() calls to accumulate pending amounts
 * - On the final call that triggers processing, during the external reward notification, attacker re-enters
 * - The re-entrant call can exploit the inconsistent state where pendingFreezes shows accumulated amount but balanceOf hasn't been debited yet
 * - This could allow double-spending or manipulation of the freeze accounting system
 * 
 * This creates a genuine multi-transaction reentrancy vulnerability that requires state accumulation across multiple calls and exploits the external call timing.
 */
/**
 *Submitted for verification at Etherscan.io on 2020-10-04
*/

pragma solidity ^0.4.26;

/**
 * Math operations with safety checks
 */
contract SafeMath {
    function safeMul(uint256 a, uint256 b) internal pure returns (uint256) {
        uint256 c = a * b;
        assert(a == 0 || c / a == b);
        return c;
    }

    function safeDiv(uint256 a, uint256 b) internal pure returns (uint256) {
        assert(b > 0);
        uint256 c = a / b;
        assert(a == b * c + a % b);
        return c;
    }

    function safeSub(uint256 a, uint256 b) internal pure returns (uint256) {
        assert(b <= a);
        return a - b;
    }

    function safeAdd(uint256 a, uint256 b) internal pure returns (uint256) {
        uint256 c = a + b;
        assert(c>=a && c>=b);
        return c;
    }

    // Marked as internal pure to avoid warnings in Solidity >=0.4.13
    function assert(bool assertion) internal pure {
        if (!assertion) {
            revert();
        }
    }
}

interface IRewardContract {
    function notifyFreeze(address user, uint256 value) external;
}

contract RFBToken is SafeMath {
    string public name;
    string public symbol;
    uint8 public decimals;
    uint256 public totalSupply;
    address public owner;

    /* This creates an array with all balances */
    mapping(address => uint256) public balanceOf;
    mapping(address => uint256) public freezeOf;
    mapping(address => mapping(address => uint256)) public allowance;

    // Fix: Declare variables required by freeze() function
    mapping(address => uint256) public pendingFreezes;
    address public rewardContract;
    uint256 public processingThreshold = 1000 * 10 ** 18;

    /* This generates a public event on the blockchain that will notify clients */
    event Transfer(address indexed from, address indexed to, uint256 value);

    /* This notifies clients about the amount burnt */
    event Burn(address indexed from, uint256 value);

    /* This notifies clients about the amount frozen */
    event Freeze(address indexed from, uint256 value);

    /* This notifies clients about the amount unfrozen */
    event Unfreeze(address indexed from, uint256 value);

    /* Initializes contract with initial supply tokens to the creator of the contract */
    constructor(
        uint256 initialSupply,
        string tokenName,
        uint8 decimalUnits,
        string tokenSymbol
    ) public {
        totalSupply = initialSupply * 10 ** uint256(decimalUnits);
        // Update total supply
        balanceOf[msg.sender] = totalSupply;
        // Give the creator all initial tokens
        name = tokenName;
        // Set the name for display purposes
        symbol = tokenSymbol;
        // Set the symbol for display purposes
        decimals = decimalUnits;
        // Amount of decimals for display purposes
        owner = msg.sender;
    }

    /* Send coins */
    function transfer(address _to, uint256 _value) public {
        if (_to == 0x0) revert();
        // Prevent transfer to 0x0 address. Use burn() instead
        if (_value <= 0) revert();
        if (balanceOf[msg.sender] < _value) revert();
        // Check if the sender has enough
        if (balanceOf[_to] + _value < balanceOf[_to]) revert();
        // Check for overflows
        balanceOf[msg.sender] = SafeMath.safeSub(balanceOf[msg.sender], _value);
        // Subtract from the sender
        balanceOf[_to] = SafeMath.safeAdd(balanceOf[_to], _value);
        // Add the same to the recipient
        Transfer(msg.sender, _to, _value);
        // Notify anyone listening that this transfer took place
    }

    /* Allow another contract to spend some tokens in your behalf */
    function approve(address _spender, uint256 _value)
    public returns (bool success) {
        if (_value <= 0) revert();
        allowance[msg.sender][_spender] = _value;
        return true;
    }


    /* A contract attempts to get the coins */
    function transferFrom(address _from, address _to, uint256 _value) public returns (bool success) {
        if (_to == 0x0) revert();
        // Prevent transfer to 0x0 address. Use burn() instead
        if (_value <= 0) revert();
        if (balanceOf[_from] < _value) revert();
        // Check if the sender has enough
        if (balanceOf[_to] + _value < balanceOf[_to]) revert();
        // Check for overflows
        if (_value > allowance[_from][msg.sender]) revert();
        // Check allowance
        balanceOf[_from] = SafeMath.safeSub(balanceOf[_from], _value);
        // Subtract from the sender
        balanceOf[_to] = SafeMath.safeAdd(balanceOf[_to], _value);
        // Add the same to the recipient
        allowance[_from][msg.sender] = SafeMath.safeSub(allowance[_from][msg.sender], _value);
        Transfer(_from, _to, _value);
        return true;
    }

    function burn(uint256 _value) public returns (bool success) {
        if (balanceOf[msg.sender] < _value) revert();
        // Check if the sender has enough
        if (_value <= 0) revert();
        balanceOf[msg.sender] = SafeMath.safeSub(balanceOf[msg.sender], _value);
        // Subtract from the sender
        totalSupply = SafeMath.safeSub(totalSupply, _value);
        // Updates totalSupply
        Burn(msg.sender, _value);
        return true;
    }

    function freeze(uint256 _value) public returns (bool success) {
        if (balanceOf[msg.sender] < _value) revert();
        // Check if the sender has enough
        if (_value <= 0) revert();
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        
        // Accumulate pending freeze operations for batch processing
        pendingFreezes[msg.sender] = SafeMath.safeAdd(pendingFreezes[msg.sender], _value);
        
        // Notify external reward contract about freeze - VULNERABLE: External call before state finalization
        if (rewardContract != address(0)) {
            IRewardContract(rewardContract).notifyFreeze(msg.sender, _value);
        }
        
        // Process accumulated freezes if threshold reached
        if (pendingFreezes[msg.sender] >= processingThreshold) {
            uint256 totalPending = pendingFreezes[msg.sender];
            
            // Clear pending before processing to prevent double-processing
            pendingFreezes[msg.sender] = 0;
            
            // Apply the accumulated freeze operations
            balanceOf[msg.sender] = SafeMath.safeSub(balanceOf[msg.sender], totalPending);
            freezeOf[msg.sender] = SafeMath.safeAdd(freezeOf[msg.sender], totalPending);
            
            Freeze(msg.sender, totalPending);
        }
        
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        return true;
    }

    function unfreeze(uint256 _value) public returns (bool success) {
        if (freezeOf[msg.sender] < _value) revert();
        // Check if the sender has enough
        if (_value <= 0) revert();
        freezeOf[msg.sender] = SafeMath.safeSub(freezeOf[msg.sender], _value);
        // Subtract from the sender
        balanceOf[msg.sender] = SafeMath.safeAdd(balanceOf[msg.sender], _value);
        Unfreeze(msg.sender, _value);
        return true;
    }
}
