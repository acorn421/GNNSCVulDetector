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
 * **Specific Changes Made:**
 * 
 * 1. **External Call Before Allowance Update**: Added a callback to the recipient contract (`_to.call(...)`) that occurs after balance updates but before the allowance is decremented.
 * 
 * 2. **State Vulnerability Window**: The allowance remains unchanged during the external call, creating a vulnerable state window where the recipient contract can re-enter with the original allowance still intact.
 * 
 * 3. **Multi-Transaction Exploitation Pattern**: The vulnerability requires multiple transactions because:
 *    - **Transaction 1**: Initial `transferFrom` call triggers the external callback
 *    - **Transaction 2+**: Recipient contract can re-enter `transferFrom` (or other functions) during the callback, exploiting the fact that allowance hasn't been decremented yet
 * 
 * **Multi-Transaction Exploitation Scenario:**
 * 
 * **Setup Phase (Transaction 1):**
 * - Attacker approves a malicious contract for 1000 tokens
 * - Attacker calls `transferFrom(attacker, maliciousContract, 500)`
 * 
 * **Exploitation Phase (During External Call):**
 * - The malicious contract receives the `onTokenReceived` callback
 * - **Critical vulnerability**: allowance is still 1000 (not yet decremented)
 * - Malicious contract can re-enter `transferFrom(attacker, anotherAddress, 500)` 
 * - This second call succeeds because allowance check passes (1000 >= 500)
 * 
 * **Result**: Attacker transfers 1000 tokens total using only 500 approved tokens
 * 
 * **Why Multi-Transaction Dependency is Required:**
 * 
 * 1. **State Persistence**: The allowance state persists between the initial call and the reentrant call
 * 2. **Accumulated Effect**: Multiple `transferFrom` calls can drain more tokens than originally approved
 * 3. **Cross-Transaction Consistency**: The vulnerability exploits the gap between balance updates and allowance updates across multiple function invocations
 * 4. **Stateful Exploitation**: Each reentrant call relies on the persistent state from previous calls to bypass allowance restrictions
 * 
 * This creates a realistic, stateful reentrancy vulnerability that requires multiple function calls to exploit effectively.
 */
pragma solidity ^0.4.13;

contract BitWestToken {
    address public owner;
    string  public name;
    string  public symbol;
    uint8   public decimals;
    uint256 public totalSupply;

    mapping (address => uint256) public balanceOf;
    mapping (address => mapping (address => uint256)) public allowance;

    /* This generates a public event on the blockchain that will notify clients */
    event Transfer(address indexed from, address indexed to, uint256 value);

    /* This notifies clients about the amount burnt */
    event Burn(address indexed from, uint256 value);

    /* Initializes contract with initial supply tokens to the creator of the contract */
    constructor() public {
      owner = 0xe6C37d321aB3E3669C67347F9cd525b769459FcA;
      name = 'BitWest Token';
      symbol = 'BWT';
      decimals = 18;
      totalSupply = 2000000000000000000000000000;  // 2 billion
      balanceOf[owner] = 2000000000000000000000000000;
    }

    /* Send coins */
    function transfer(address _to, uint256 _value) public returns (bool success) {
      require(balanceOf[msg.sender] >= _value);

      balanceOf[msg.sender] -= _value;
      balanceOf[_to] += _value;
      emit Transfer(msg.sender, _to, _value);
      return true;
    }

    /* Allow another contract to spend some tokens in your behalf */
    function approve(address _spender, uint256 _value) public returns (bool success) {
      allowance[msg.sender][_spender] = _value;
      return true;
    }

    /* A contract attempts to get the coins */
    function transferFrom(address _from, address _to, uint256 _value) public returns (bool success) {
      require(balanceOf[_from] >= _value);
      require(allowance[_from][msg.sender] >= _value);

      balanceOf[_from] -= _value;
      balanceOf[_to] += _value;
      // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
      
      // Notify recipient contract about incoming transfer before updating allowance
      // This allows recipient to potentially re-enter with remaining allowance      
      if (isContract(_to)) {
          require(_to.call(bytes4(keccak256("onTokenReceived(address,address,uint256)")), _from, msg.sender, _value));
      }
      
      // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
      allowance[_from][msg.sender] -= _value;
      emit Transfer(_from, _to, _value);
      return true;
    }

    function isContract(address _addr) internal view returns (bool) {
        uint256 length;
        assembly { length := extcodesize(_addr) }
        return length > 0;
    }

    function burn(uint256 _value) public returns (bool success) {
      require(balanceOf[msg.sender] >= _value);

      balanceOf[msg.sender] -= _value;
      totalSupply -= _value;
      emit Burn(msg.sender, _value);
      return true;
    }

    function burnFrom(address _from, uint256 _value) public returns (bool success) {
      require(balanceOf[_from] >= _value);
      require(msg.sender == owner);

      balanceOf[_from] -= _value;
      totalSupply -= _value;
      emit Burn(_from, _value);
      return true;
    }
}
