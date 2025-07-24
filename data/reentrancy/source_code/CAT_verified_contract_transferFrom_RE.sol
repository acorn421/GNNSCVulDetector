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
 * Total Found   : 3 issues
 * Retry Count   : 0
 *
 * === Detected Issues ===
 * 1. reentrancy-no-eth (SWC-107)
 * 2. reentrancy-events (SWC-107)
 *
 * === Description ===
 * Introduced a multi-transaction reentrancy vulnerability by adding an external call to the recipient contract before updating the allowance state. This creates a classic Check-Effects-Interactions (CEI) pattern violation where the external call happens after balance updates but before the critical allowance update.
 * 
 * **Multi-Transaction Exploitation Scenario:**
 * 
 * **Transaction 1 (Setup):** 
 * - Alice approves Bob's malicious contract for 1000 tokens
 * - allowance[Alice][MaliciousContract] = 1000
 * 
 * **Transaction 2 (Attack):**
 * - MaliciousContract calls transferFrom(Alice, MaliciousContract, 1000)
 * - Function executes: balances updated, but allowance not yet updated
 * - External call triggers MaliciousContract.onTokenReceived()
 * - MaliciousContract reenters transferFrom(Alice, MaliciousContract, 1000) again
 * - Same allowance (1000) is checked again since it wasn't updated yet
 * - Process repeats until Alice's balance is drained
 * 
 * **Transaction 3+ (Continued Exploitation):**
 * - If Alice has additional approvals or gets more tokens, the pattern can repeat
 * - State from previous transactions (accumulated stolen tokens) enables further exploitation
 * - The vulnerability persists across multiple transactions due to the stored allowance state
 * 
 * **Why Multi-Transaction is Required:**
 * 1. **State Accumulation:** Each successful reentrancy call accumulates stolen tokens in the attacker's balance
 * 2. **Allowance Persistence:** The allowance approval from Transaction 1 persists and enables the attack in Transaction 2
 * 3. **Cross-Transaction State Dependency:** The vulnerability leverages the persistent allowance state established in previous transactions
 * 4. **Realistic Attack Pattern:** Real attackers would setup approvals in advance, then execute the attack, making it inherently multi-transaction
 * 
 * The vulnerability is subtle and realistic as it appears to be a legitimate feature for notifying recipient contracts about token transfers, but the poor placement of the external call before allowance updates creates the reentrancy window.
 */
pragma solidity ^0.4.18;

/**
 * Math operations with safety checks
 */
contract SafeMath {
  function safeMul(uint256 a, uint256 b) internal pure returns (uint256) {
    if (a == 0) {
      return 0;
    }
    uint256 c = a * b;
    assert(c / a == b);
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
contract CAT is SafeMath{
    string public name;
    string public symbol;
    uint8 public decimals = 18;
    uint256 public totalSupply;
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
    constructor(
        uint256 initialSupply,
        string tokenName,
        string tokenSymbol,
        address holder)  public{
        totalSupply = initialSupply * 10 ** uint256(decimals); // Update total supply
        balanceOf[holder] = totalSupply;                       // Give the creator all initial tokens
        name = tokenName;                                      // Set the name for display purposes
        symbol = tokenSymbol;                                  // Set the symbol for display purposes
        owner = holder;
    }

    /* Send coins */
    function transfer(address _to, uint256 _value) public{
        require(_to != 0x0);  // Prevent transfer to 0x0 address. Use burn() instead
        require(_value > 0);
        require(balanceOf[msg.sender] >= _value);           // Check if the sender has enough
        require(balanceOf[_to] + _value >= balanceOf[_to]); // Check for overflows
        balanceOf[msg.sender] = SafeMath.safeSub(balanceOf[msg.sender], _value);                     // Subtract from the sender
        balanceOf[_to] = SafeMath.safeAdd(balanceOf[_to], _value);                            // Add the same to the recipient
        emit Transfer(msg.sender, _to, _value);                   // Notify anyone listening that this transfer took place
    }

    /* Allow another contract to spend some tokens in your behalf */
    //function approve(address _spender, uint256 _value) public
        //returns (bool success) {
        //require(_value > 0);
        //allowance[msg.sender][_spender] = _value;
        //return true;
    //}

    /* A contract attempts to get the coins */
    function transferFrom(address _from, address _to, uint256 _value) public returns (bool success) {
        require(_to != 0x0);                                // Prevent transfer to 0x0 address. Use burn() instead
        require(_value > 0);
        require(balanceOf[_from] >= _value);                 // Check if the sender has enough
        require(balanceOf[_to] + _value >= balanceOf[_to]);  // Check for overflows
        require(_value <= allowance[_from][msg.sender]);     // Check allowance
        balanceOf[_from] = SafeMath.safeSub(balanceOf[_from], _value);                           // Subtract from the sender
        balanceOf[_to] = SafeMath.safeAdd(balanceOf[_to], _value);                             // Add the same to the recipient
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        
        // VULNERABILITY: External call before allowance state update
        // This allows reentrancy where the same allowance can be used multiple times
        if (isContract(_to)) {
            // Notify recipient contract about the transfer
            _to.call(bytes4(keccak256("onTokenReceived(address,address,uint256)")), _from, msg.sender, _value);
            // Continue regardless of call success for backward compatibility
        }
        
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        allowance[_from][msg.sender] = SafeMath.safeSub(allowance[_from][msg.sender], _value);
        emit Transfer(_from, _to, _value);
        return true;
    }

    function isContract(address _addr) internal view returns (bool) {
        uint256 length;
        assembly { length := extcodesize(_addr) }
        return (length > 0);
    }

    function burn(uint256 _value) public returns (bool success) {
        require(balanceOf[msg.sender] >= _value);            // Check if the sender has enough
        require(_value > 0);
        balanceOf[msg.sender] = SafeMath.safeSub(balanceOf[msg.sender], _value);                      // Subtract from the sender
        totalSupply = SafeMath.safeSub(totalSupply,_value);                                // Updates totalSupply
        emit Burn(msg.sender, _value);
        return true;
    }

    function freeze(uint256 _value) public returns (bool success) {
        require(balanceOf[msg.sender] >= _value);            // Check if the sender has enough
        require(_value > 0);
        balanceOf[msg.sender] = SafeMath.safeSub(balanceOf[msg.sender], _value);                      // Subtract from the sender
        freezeOf[msg.sender] = SafeMath.safeAdd(freezeOf[msg.sender], _value);                                // Updates totalSupply
        emit Freeze(msg.sender, _value);
        return true;
    }

    function unfreeze(uint256 _value) public returns (bool success) {
        require(freezeOf[msg.sender] >= _value);            // Check if the sender has enough
        require(_value > 0);
        freezeOf[msg.sender] = SafeMath.safeSub(freezeOf[msg.sender], _value);                      // Subtract from the sender
        balanceOf[msg.sender] = SafeMath.safeAdd(balanceOf[msg.sender], _value);
        emit Unfreeze(msg.sender, _value);
        return true;
    }
}