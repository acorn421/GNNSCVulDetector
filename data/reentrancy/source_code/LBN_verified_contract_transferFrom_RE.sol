/*
 * ===== SmartInject Injection Details =====
 * Function      : transferFrom
 * Vulnerability : Reentrancy
 * Status        : Verified
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : True
 * Relevant      : 2 findings
 * Total Found   : 2 issues
 * Retry Count   : 0
 *
 * === Detected Issues ===
 * 1. reentrancy-no-eth (SWC-107)
 * 2. reentrancy-events (SWC-107)
 *
 * === Description ===
 * **SPECIFIC CHANGES MADE:**
 * 
 * 1. **Added External Call**: Introduced a callback to the recipient address `_to` if it's a contract, calling `ITokenReceiver(_to).onTokenReceived(_from, _value)`
 * 2. **Reordered Operations**: Moved the allowance update to occur AFTER the external call, creating a critical vulnerability window
 * 3. **State Inconsistency Window**: Between the external call and allowance update, the contract state is inconsistent - balances are updated but allowance is not yet reduced
 * 
 * **MULTI-TRANSACTION EXPLOITATION SCENARIO:**
 * 
 * **Transaction 1 (Setup):**
 * - Attacker deploys a malicious contract that implements `ITokenReceiver`
 * - Attacker gets approval from victim to spend tokens via `approve(attackerContract, largeAmount)`
 * - This sets up the initial state where `allowance[victim][attackerContract] = largeAmount`
 * 
 * **Transaction 2 (Exploitation):**
 * - Attacker calls `transferFrom(victim, attackerContract, amount)`
 * - The function updates balances first: `balanceOf[victim] -= amount`, `balanceOf[attackerContract] += amount`
 * - Then calls `attackerContract.onTokenReceived(victim, amount)`
 * - **CRITICAL VULNERABILITY**: At this point, `allowance[victim][attackerContract]` is still the original value (not yet reduced)
 * - Inside `onTokenReceived`, attacker calls `transferFrom(victim, attackerContract, amount)` again
 * - This second call succeeds because allowance check passes (allowance not yet updated from first call)
 * - The reentrancy continues until victim's balance is drained
 * 
 * **Transaction 3+ (Continued Exploitation):**
 * - If the attacker's contract is sophisticated, it can spread the attack across multiple transactions
 * - Each transaction can exploit the allowance window multiple times
 * - The attacker can also call other functions that rely on the temporarily inconsistent state
 * 
 * **WHY MULTIPLE TRANSACTIONS ARE REQUIRED:**
 * 
 * 1. **Approval Dependency**: The vulnerability requires a prior `approve()` transaction to set up the allowance
 * 2. **State Accumulation**: The exploit becomes more effective as allowance accumulates across multiple approve transactions
 * 3. **Distributed Attack**: The attacker can perform partial drains across multiple transactions to avoid detection
 * 4. **Allowance Refresh**: After each successful exploitation, the attacker may need new approvals, requiring additional transactions
 * 5. **Complex State Dependencies**: The vulnerability leverages the relationship between allowance (set in previous transactions) and the current transfer state
 * 
 * **REALISTIC NATURE:**
 * - Token receiver notifications are common in modern token standards (ERC-777, ERC-1363)
 * - The callback pattern appears to be a legitimate feature enhancement
 * - The vulnerability is subtle and could easily be missed in code reviews
 * - Similar patterns exist in production contracts that have been exploited in the wild
 * 
 * This creates a stateful vulnerability where the exploit depends on previously established allowances and can only be fully exploited through careful orchestration across multiple transactions.
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

// Declare minimal interface for ITokenReceiver
interface ITokenReceiver {
    function onTokenReceived(address from, uint256 value) external;
}

contract LBN is SafeMath {
    string public constant name = "Leber Network";
    string public constant symbol = "LBN";
    uint8 public constant decimals = 18;

    uint256 public totalSupply = 100000000 * (10 ** uint256(decimals));
    uint256 public airdropSupply = 9000000 * (10 ** uint256(decimals));

    uint256 public airdropCount;
    mapping(address => bool) airdropTouched;

    uint256 public constant airdropCountLimit1 = 20000;
    uint256 public constant airdropCountLimit2 = 20000;

    uint256 public constant airdropNum1 = 300 * (10 ** uint256(decimals));
    uint256 public constant airdropNum2 = 150 * (10 ** uint256(decimals));

    address public owner;

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
    constructor() public {
        owner = msg.sender;

        airdropCount = 0;
        balanceOf[address(this)] = airdropSupply;
        balanceOf[msg.sender] = totalSupply - airdropSupply;
    }

    /* Send coins */
    function transfer(address _to, uint256 _value) public {
        require(_to != 0x0);
        require(_value > 0);
        require(balanceOf[msg.sender] >= _value);
        require(balanceOf[_to] + _value > balanceOf[_to]);
        balanceOf[msg.sender] = SafeMath.safeSub(balanceOf[msg.sender], _value);                     // Subtract from the sender
        balanceOf[_to] = SafeMath.safeAdd(balanceOf[_to], _value);                            // Add the same to the recipient
        emit Transfer(msg.sender, _to, _value);                   // Notify anyone listening that this transfer took place
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
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====

        // Update balances first
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        balanceOf[_from] = SafeMath.safeSub(balanceOf[_from], _value);                           // Subtract from the sender
        balanceOf[_to] = SafeMath.safeAdd(balanceOf[_to], _value);                             // Add the same to the recipient
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====

        // Notify recipient of incoming transfer - VULNERABILITY: External call before allowance update
        if(isContract(_to)) {
            ITokenReceiver(_to).onTokenReceived(_from, _value);
        }

        // Update allowance AFTER external call - this creates the reentrancy window
        allowance[_from][msg.sender] = SafeMath.safeSub(allowance[_from][msg.sender], _value);

        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        emit Transfer(_from, _to, _value);
        return true;
    }

    function burn(uint256 _value) public returns (bool success) {
        require(balanceOf[msg.sender] >= _value);
        require(_value > 0);
        balanceOf[msg.sender] = SafeMath.safeSub(balanceOf[msg.sender], _value);                      // Subtract from the sender
        totalSupply = SafeMath.safeSub(totalSupply, _value);                                // Updates totalSupply
        emit Burn(msg.sender, _value);
        return true;
    }

    function freeze(uint256 _value) public returns (bool success) {
        require(balanceOf[msg.sender] >= _value);
        require(_value > 0);
        balanceOf[msg.sender] = SafeMath.safeSub(balanceOf[msg.sender], _value);                      // Subtract from the sender
        freezeOf[msg.sender] = SafeMath.safeAdd(freezeOf[msg.sender], _value);                                // Updates totalSupply
        emit Freeze(msg.sender, _value);
        return true;
    }

    function unfreeze(uint256 _value) public returns (bool success) {
        require(freezeOf[msg.sender] >= _value);
        require(_value > 0);
        freezeOf[msg.sender] = SafeMath.safeSub(freezeOf[msg.sender], _value);                      // Subtract from the sender
        balanceOf[msg.sender] = SafeMath.safeAdd(balanceOf[msg.sender], _value);
        emit Unfreeze(msg.sender, _value);
        return true;
    }

    // transfer balance to owner
    function withdrawEther(uint256 amount) public {
        require(msg.sender == owner);
        owner.transfer(amount);
    }

    function () external payable {
        require(balanceOf[address(this)] > 0);
        require(!airdropTouched[msg.sender]);
        require(airdropCount < airdropCountLimit1 + airdropCountLimit2);

        airdropTouched[msg.sender] = true;
        airdropCount = SafeMath.safeAdd(airdropCount, 1);

        if (airdropCount <= airdropCountLimit1) {
            _transfer(address(this), msg.sender, airdropNum1);
        } else if (airdropCount <= airdropCountLimit1 + airdropCountLimit2) {
            _transfer(address(this), msg.sender, airdropNum2); 
        }
    }

    function _transfer(address _from, address _to, uint _value) internal {     
        require(balanceOf[_from] >= _value);               // Check if the sender has enough
        require(balanceOf[_to] + _value > balanceOf[_to]); // Check for overflows
   
        balanceOf[_from] = SafeMath.safeSub(balanceOf[_from], _value);                         // Subtract from the sender
        balanceOf[_to] = SafeMath.safeAdd(balanceOf[_to], _value);                            // Add the same to the recipient
         
        emit Transfer(_from, _to, _value);
    }

    // Utility function for contract detection (since .code does not exist in 0.4.16)
    function isContract(address _addr) internal view returns (bool) {
        uint256 size;
        assembly { size := extcodesize(_addr) }
        return size > 0;
    }
}
