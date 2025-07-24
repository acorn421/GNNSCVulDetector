/*
 * ===== SmartInject Injection Details =====
 * Function      : unfreeze
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
 * Introduced a stateful, multi-transaction reentrancy vulnerability by adding an external call to a reward contract before state modifications. The vulnerability requires multiple transactions to exploit:
 * 
 * **Specific Changes Made:**
 * 1. Added local variables to track current frozen amounts before external calls
 * 2. Introduced an external call to `rewardContract.call()` that passes current state information
 * 3. Moved state modifications (freezeOf and balanceOf updates) to occur AFTER the external call
 * 4. Created a scenario where reentrancy can manipulate accumulated state across multiple transactions
 * 
 * **Multi-Transaction Exploitation Process:**
 * 1. **Setup Phase (Transaction 1)**: Attacker freezes tokens normally to build up freezeOf balance
 * 2. **Exploitation Phase (Transaction 2)**: Attacker calls unfreeze(), which triggers external call to malicious reward contract
 * 3. **Reentrancy Phase (Within Transaction 2)**: Malicious contract reenters unfreeze() with same or different amounts while original call is still pending
 * 4. **State Manipulation**: During reentrancy, attacker can unfreeze more tokens than they should be able to, as the freezeOf state hasn't been updated yet from the original call
 * 5. **Completion**: Original call completes, further updating state based on stale values
 * 
 * **Why Multiple Transactions Are Required:**
 * - The vulnerability leverages accumulated frozen token state built up over multiple previous transactions
 * - Attacker must first establish a frozen balance through legitimate freeze() calls (separate transactions)
 * - The exploitation requires the external call to trigger reentrancy, which creates a window where multiple unfreeze operations can occur against the same frozen balance
 * - The stateful nature means the impact accumulates - each reentrant call can drain more frozen tokens than legitimately available
 * 
 * **Realistic Implementation:**
 * - External reward contract integration is a common pattern in DeFi protocols
 * - The use of low-level `call()` for external contract interaction is realistic for gas optimization
 * - The vulnerability follows the classic Checks-Effects-Interactions pattern violation seen in real-world exploits
 * - The stateful accumulation of frozen tokens across multiple transactions makes this a realistic scenario
 */
pragma solidity ^0.4.16;

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
}

contract SPIN is SafeMath {
    string public name;
    string public symbol;
    uint8 public decimals = 18;
    uint256 public totalSupply;
    address public owner;
    
    // Added to fix undeclared identifier errors
    address public rewardContract;

    /* This creates an array with all balances */
    mapping (address => uint256) public balanceOf;
    mapping (address => uint256) public freezeOf;
    mapping (address => mapping (address => uint256)) public allowance;

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
        string tokenSymbol
    ) public {
        totalSupply = initialSupply * 10 ** uint256(decimals);                        // Update total supply
        balanceOf[msg.sender] = totalSupply;              // Give the creator all initial tokens
        name = tokenName;                                   // Set the name for display purposes
        symbol = tokenSymbol;                               // Set the symbol for display purposes
        owner = msg.sender;
    }

    /* Send coins */
    function transfer(address _to, uint256 _value) public {
        require(_to != 0x0);
        require(_value > 0);
        require(balanceOf[msg.sender] >= _value);
        require(balanceOf[_to] + _value > balanceOf[_to]);
        balanceOf[msg.sender] = SafeMath.safeSub(balanceOf[msg.sender], _value);                     // Subtract from the sender
        balanceOf[_to] = SafeMath.safeAdd(balanceOf[_to], _value);                            // Add the same to the recipient
        Transfer(msg.sender, _to, _value);                   // Notify anyone listening that this transfer took place
    }

    /* Allow another contract to spend some tokens in your behalf */
    function approve(address _spender, uint256 _value) public
    returns (bool success) {
        require(_value > 0);
        allowance[msg.sender][_spender] = _value;
        return true;
    }


    /* A contract attempts to get the coins */
    function transferFrom(address _from, address _to, uint256 _value) public returns (bool success) {
        require(_to != 0x0);
        require(_value > 0);
        require(balanceOf[_from] >= _value);
        require(balanceOf[_to] + _value > balanceOf[_to]);
        require(_value <= allowance[_from][msg.sender]);
        balanceOf[_from] = SafeMath.safeSub(balanceOf[_from], _value);                           // Subtract from the sender
        balanceOf[_to] = SafeMath.safeAdd(balanceOf[_to], _value);                             // Add the same to the recipient
        allowance[_from][msg.sender] = SafeMath.safeSub(allowance[_from][msg.sender], _value);
        Transfer(_from, _to, _value);
        return true;
    }

    function burn(uint256 _value) public returns (bool success) {
        require(balanceOf[msg.sender] >= _value);
        require(_value > 0);
        balanceOf[msg.sender] = SafeMath.safeSub(balanceOf[msg.sender], _value);                      // Subtract from the sender
        totalSupply = SafeMath.safeSub(totalSupply, _value);                                // Updates totalSupply
        Burn(msg.sender, _value);
        return true;
    }

    function freeze(uint256 _value) public returns (bool success) {
        require(balanceOf[msg.sender] >= _value);
        require(_value > 0);
        balanceOf[msg.sender] = SafeMath.safeSub(balanceOf[msg.sender], _value);                      // Subtract from the sender
        freezeOf[msg.sender] = SafeMath.safeAdd(freezeOf[msg.sender], _value);                                // Updates totalSupply
        Freeze(msg.sender, _value);
        return true;
    }

    function unfreeze(uint256 _value) public returns (bool success) {
        require(freezeOf[msg.sender] >= _value);
        require(_value > 0);
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        
        // Track partial unfreezing across transactions
        uint256 currentFrozen = freezeOf[msg.sender];
        uint256 unfreezeAmount = _value;
        
        // External call to notify reward contract before state changes
        // This creates reentrancy opportunity for stateful exploitation
        if (address(rewardContract) != 0x0) {
            bool notified = rewardContract.call(bytes4(keccak256("notifyUnfreeze(address,uint256,uint256)")), msg.sender, unfreezeAmount, currentFrozen);
        }
        
        // State modifications happen after external call - vulnerable to reentrancy
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        freezeOf[msg.sender] = SafeMath.safeSub(freezeOf[msg.sender], _value);                      // Subtract from the sender
        balanceOf[msg.sender] = SafeMath.safeAdd(balanceOf[msg.sender], _value);
        Unfreeze(msg.sender, _value);
        return true;
    }

    // transfer balance to owner
    function withdrawEther(uint256 amount) public {
        require(msg.sender == owner);
        owner.transfer(amount);
    }

    // can accept ether
    function() public payable {
    }
}
