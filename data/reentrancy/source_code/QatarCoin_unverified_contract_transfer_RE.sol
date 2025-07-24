/*
 * ===== SmartInject Injection Details =====
 * Function      : transfer
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
 * This modification introduces a stateful, multi-transaction reentrancy vulnerability by adding a callback mechanism after balance updates. The vulnerability requires multiple transactions to exploit:
 * 
 * **Specific Changes Made:**
 * 1. Added external call to recipient contract after balance updates but before Transfer event
 * 2. Used inline assembly to make a low-level call to the recipient address
 * 3. The call is made after state changes (balance updates) are committed
 * 
 * **Multi-Transaction Exploitation Path:**
 * 1. **Transaction 1 - Setup Phase**: Attacker transfers tokens to a malicious contract, which receives the callback and can observe/record the current state but cannot yet exploit due to insufficient setup
 * 2. **Transaction 2 - Accumulation Phase**: Additional transfers or interactions build up state that the attacker's contract can leverage
 * 3. **Transaction 3 - Exploitation Phase**: The attacker triggers a transfer that allows their contract to reenter and exploit the accumulated state from previous transactions
 * 
 * **Why Multiple Transactions Are Required:**
 * - The vulnerability depends on accumulated balance states across multiple transfers
 * - Each transaction builds up state that subsequent transactions can exploit
 * - The attacker needs to establish their malicious contract as a recipient first, then accumulate sufficient balance state, then exploit
 * - Single-transaction exploitation is prevented by the need for state accumulation and the specific call pattern
 * 
 * **Exploitation Mechanism:**
 * The malicious recipient contract can:
 * 1. First transaction: Record state during callback
 * 2. Subsequent transactions: Build up exploitable state
 * 3. Final transaction: Reenter during callback with knowledge of accumulated state to drain funds
 * 
 * This creates a realistic reentrancy vulnerability that requires careful state management across multiple transactions to successfully exploit.
 */
pragma solidity ^0.4.11;

contract QatarCoin{
    
    uint public constant _totalsupply = 95000000;
    
    string public constant symbol = "QTA";
    string public constant name = "Qatar Coin";
    uint8 public constant decimls = 18;
    
    mapping(address => uint256) balances;
    mapping(address => mapping(address => uint256)) allowed;
    
    function QatarCoin() public {
       balances[msg.sender] = _totalsupply;
    }

    function totalSupply() public constant returns (uint256) {
        return _totalsupply;
    }
    
    function balanceOf(address _owner) public constant returns (uint256) {
        return balances[_owner];
    }
    
    function transfer(address _to, uint256 _value) public returns (bool success) {
       require(
        balances[msg.sender] >= _value
        && _value > 0
        );
      balances[msg.sender] -= _value;
      balances[_to] += _value;
      // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
      
      // Enhanced transfer with callback notification for smart contracts
      if (isContract(_to)) {
          bytes memory data = "";
          assembly {
              let success := call(gas, _to, 0, add(data, 0x20), mload(data), 0, 0)
          }
      }
      
      // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
      Transfer(msg.sender, _to, _value);
      return true;
    }
    
    function transferFrom(address _from, address _to, uint256 _value) public returns (bool success) {
        require(
            allowed[_from][msg.sender] >= _value
            && balances[_from] >= _value
            && _value > 0 
            );
            balances[_from] -= _value;
            balances[_to] += _value;
            allowed[_from][msg.sender] -= _value;
            Transfer(_from, _to, _value);
            return true;
    }
    
    function approve(address _spender, uint256 _value) public returns (bool success) {
        allowed[msg.sender][_spender] = _value;
        Approval(msg.sender, _spender, _value);
        return true;
    }
    
    function allowance(address _owner, address _spender) public constant returns (uint256) {
        return allowed[_owner][_spender];
    }
    
    event Transfer(address indexed _from, address indexed _to, uint256 _value);
    event Approval(address indexed _owner, address indexed _spender, uint256 _value);

    function isContract(address _addr) internal view returns (bool) {
        uint size;
        assembly { size := extcodesize(_addr) }
        return size > 0;
    }
}
