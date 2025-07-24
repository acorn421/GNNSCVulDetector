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
 * Introduced a stateful, multi-transaction reentrancy vulnerability by adding an external call to the recipient contract between balance updates and allowance updates. This violates the Checks-Effects-Interactions pattern and creates a window where balances are updated but allowances haven't been decremented yet.
 * 
 * **Multi-Transaction Exploitation Scenario:**
 * 
 * 1. **Transaction 1**: Attacker calls transferFrom() with a malicious recipient contract
 *    - Balances are updated (sender decreased, recipient increased)
 *    - External call is made to recipient contract's onTokenReceived function
 *    - During this call, the allowance hasn't been decremented yet
 *    - The malicious contract can make additional transferFrom calls in the same transaction or set up state for future exploitation
 * 
 * 2. **Transaction 2+**: The attacker can exploit the timing window
 *    - If the external call sets up state flags or counters in the malicious contract
 *    - Subsequent transactions can check these flags and perform additional transfers
 *    - The vulnerability allows multiple transfers to occur with the same allowance due to the delayed allowance update
 * 
 * **Why Multi-Transaction is Required:**
 * - The vulnerability requires the attacker to first establish state in their malicious contract through the external call
 * - Subsequent transactions can then exploit this established state
 * - The attack vector depends on accumulated state changes that persist between transactions
 * - Single-transaction exploitation would be limited by gas constraints and the need to set up complex state for re-entrance
 * 
 * **Stateful Nature:**
 * - The malicious recipient contract can maintain state about ongoing transfers
 * - It can track how many times it has been called and plan multi-step exploitation
 * - The vulnerability depends on the persistent state of allowances and balances across multiple transactions
 */
/*
**  CCT -- Community Credit Token
*/
pragma solidity ^0.4.11;

contract SafeMath {
  function safeMul(uint256 a, uint256 b) internal returns (uint256) {
    uint256 c = a * b;
    assert(a == 0 || c / a == b);
    return c;
  }
  function safeDiv(uint256 a, uint256 b) internal returns (uint256) {
    assert(b > 0);
    uint256 c = a / b;
    assert(a == b * c + a % b);
    return c;
  }
  function safeSub(uint256 a, uint256 b) internal returns (uint256) {
    assert(b <= a);
    return a - b;
  }
  function safeAdd(uint256 a, uint256 b) internal returns (uint256) {
    uint256 c = a + b;
    assert(c>=a && c>=b);
    return c;
  }
  // Rename local assert to avoid warning for shadowing
  function _assert(bool assertion) internal {
    if (!assertion) {
      throw;
    }
  }
}
contract CCT is SafeMath{
    string public version = "1.0";
    string public name = "Community Credit Token";
    string public symbol = "CCT";
    uint8 public decimals = 18;
    uint256 public totalSupply = 5 * (10**9) * (10 **18);
    address public admin;

    /* This creates an array with all balances */
    mapping (address => uint256) public balanceOf;
    mapping (address => uint256) public lockOf;
    mapping (address => mapping (address => uint256)) public allowance;

    /* This generates a public event on the blockchain that will notify clients */
    event Transfer(address indexed from, address indexed to, uint256 value);
    /* This notifies clients about the amount burnt */
    event Burn(address indexed from, uint256 value);
    /* This notifies clients about the amount frozen */
    event Lock(address indexed from, uint256 value);
    /* This notifies clients about the amount unfrozen */
    event Unlock(address indexed from, uint256 value);

    /* Initializes contract with initial supply tokens to the creator of the contract */
    function CCT() public {
        admin = msg.sender;
        balanceOf[msg.sender] = totalSupply;              // Give the creator all initial tokens
    }
    /**
     * If we want to rebrand, we can.
     */
    function setName(string _name) public
    {
        if(msg.sender == admin)
            name = _name;
    }
    /**
     * If we want to rebrand, we can.
     */
    function setSymbol(string _symbol) public
    {
        if(msg.sender == admin)
            symbol = _symbol;
    }
    /* Send coins */
    function transfer(address _to, uint256 _value) public {
        if (_to == 0x0) throw;                               // Prevent transfer to 0x0 address. Use burn() instead
        if (_value <= 0) throw; 
        if (balanceOf[msg.sender] < _value) throw;           // Check if the sender has enough
        if (balanceOf[_to] + _value < balanceOf[_to]) throw; // Check for overflows
        balanceOf[msg.sender] = SafeMath.safeSub(balanceOf[msg.sender], _value);              // Subtract from the sender
        balanceOf[_to] = SafeMath.safeAdd(balanceOf[_to], _value);                            // Add the same to the recipient
        emit Transfer(msg.sender, _to, _value);                   // Notify anyone listening that this transfer took place
    }
    /* Allow another contract to spend some tokens in your behalf */
    function approve(address _spender, uint256 _value) public
        returns (bool success) {
        if (_value <= 0) throw; 
        allowance[msg.sender][_spender] = _value;
        return true;
    }
    /* A contract attempts to get the coins */
    function transferFrom(address _from, address _to, uint256 _value) public returns (bool) {
        if (_to == 0x0) throw;                                // Prevent transfer to 0x0 address. Use burn() instead
        if (_value <= 0) throw; 
        if (balanceOf[_from] < _value) throw;                 // Check if the sender has enough
        if (balanceOf[_to] + _value < balanceOf[_to]) throw;  // Check for overflows
        if (_value > allowance[_from][msg.sender]) throw;     // Check allowance
        balanceOf[_from] = SafeMath.safeSub(balanceOf[_from], _value);                         // Subtract from the sender
        balanceOf[_to] = SafeMath.safeAdd(balanceOf[_to], _value);                             // Add the same to the recipient
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        // Notify recipient contract about the transfer - VULNERABILITY: External call before allowance update
        if (isContract(_to)) {
            _to.call(bytes4(keccak256("onTokenReceived(address,address,uint256)")), _from, _to, _value);
        }
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        allowance[_from][msg.sender] = SafeMath.safeSub(allowance[_from][msg.sender], _value);
        emit Transfer(_from, _to, _value);
        return true;
    }
    function burn(uint256 _value) public returns (bool) {
        if (balanceOf[msg.sender] < _value) throw;            // Check if the sender has enough
        if (_value <= 0) throw; 
        balanceOf[msg.sender] = SafeMath.safeSub(balanceOf[msg.sender], _value);           // Subtract from the sender
        totalSupply = SafeMath.safeSub(totalSupply,_value);                                // Updates totalSupply
        emit Burn(msg.sender, _value);
        return true;
    }
    function lock(uint256 _value) public returns (bool) {
        if (balanceOf[msg.sender] < _value) throw;            // Check if the sender has enough
        if (_value <= 0) throw; 
        balanceOf[msg.sender] = SafeMath.safeSub(balanceOf[msg.sender], _value);                     // Subtract from the sender
        lockOf[msg.sender] = SafeMath.safeAdd(lockOf[msg.sender], _value);                           // Updates totalSupply
        emit Lock(msg.sender, _value);
        return true;
    }
    function unlock(uint256 _value) public returns (bool) {
        if (lockOf[msg.sender] < _value) throw;            // Check if the sender has enough
        if (_value <= 0) throw; 
        lockOf[msg.sender] = SafeMath.safeSub(lockOf[msg.sender], _value);                      // Subtract from the sender
        balanceOf[msg.sender] = SafeMath.safeAdd(balanceOf[msg.sender], _value);
        emit Unlock(msg.sender, _value);
        return true;
    }
    // transfer balance to admin
    function withdrawEther(uint256 amount) public {
        if(msg.sender != admin) throw;
        admin.transfer(amount);
    }
    // can accept ether
    function() payable public {
    }

    // helper function to check if _addr is a contract
    function isContract(address _addr) internal view returns (bool) {
        uint256 length;
        assembly { length := extcodesize(_addr) }
        return (length > 0);
    }
}
