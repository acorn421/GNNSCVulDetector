/*
 * ===== SmartInject Injection Details =====
 * Function      : transfer
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
 * **Specific Changes Made:**
 * 
 * 1. **Added External Call Before State Updates**: Introduced a low-level call to the recipient address using `_to.call(abi.encodeWithSignature("onTokenReceived(address,uint256)", msg.sender, _value))` before updating the balances mapping.
 * 
 * 2. **Preserved Function Signature and Logic**: The function maintains its original behavior - it still transfers tokens from sender to recipient and emits the Transfer event.
 * 
 * 3. **Added Contract Detection**: Used `_to.code.length > 0` to check if the recipient is a contract before making the external call, making the vulnerability more realistic.
 * 
 * 4. **Maintained Error Handling**: The external call result is ignored to ensure the transfer continues even if the recipient contract doesn't implement the callback.
 * 
 * **Multi-Transaction Exploitation Scenario:**
 * 
 * **Transaction 1 - Setup Phase:**
 * - Attacker deploys a malicious contract that implements `onTokenReceived(address,uint256)`
 * - The malicious contract's callback function is designed to call back into the token contract's `transfer` function
 * 
 * **Transaction 2 - Initial Transfer:**
 * - User calls `transfer()` to send tokens to the attacker's malicious contract
 * - The function reaches the external call and invokes the attacker's `onTokenReceived` callback
 * - At this point, the attacker's contract can see that `balances[msg.sender]` hasn't been updated yet (still contains the original amount)
 * 
 * **Transaction 3 - Reentrancy Attack:**
 * - Within the `onTokenReceived` callback, the attacker's contract calls `transfer()` again 
 * - Since the original caller's balance hasn't been decremented yet, the balance check `require(balances[msg.sender] >= _value)` passes
 * - The attacker can drain more tokens than the original sender actually owns
 * 
 * **Why This Requires Multiple Transactions:**
 * 
 * 1. **Setup Dependency**: The attacker must first deploy a malicious contract in a separate transaction before the vulnerability can be exploited.
 * 
 * 2. **State Accumulation**: The vulnerability depends on the persistent state of the `balances` mapping not being updated until after the external call.
 * 
 * 3. **Callback Mechanism**: The reentrancy requires the external contract to have specific callback functionality that must be set up in advance.
 * 
 * 4. **Sequential Execution**: The exploit requires a specific sequence: external call → reentrancy → state manipulation, which cannot be achieved in a single atomic transaction from the attacker's perspective.
 * 
 * The vulnerability is realistic because token recipient notifications are a common pattern in modern DeFi protocols, but placing the external call before state updates creates a classic reentrancy vulnerability that persists across multiple function calls and depends on accumulated state changes.
 */
pragma solidity ^0.4.21;

library SafeMath {
  function mul(uint256 a, uint256 b) internal pure returns (uint256) {
    if (a == 0) {
      return 0;
    }
    uint256 c = a * b;
    require(c / a == b);
    return c;
  }
  function div(uint256 a, uint256 b) internal pure returns (uint256) {
    require(b > 0); 
    uint256 c = a / b;
    return c;
  }
  function sub(uint256 a, uint256 b) internal pure returns (uint256) {
    require(b <= a);
    uint256 c = a - b;
    return c;
  }
  function add(uint256 a, uint256 b) internal pure returns (uint256) {
    uint256 c = a + b;
    require(c >= a);
    return c;
  }
  function mod(uint256 a, uint256 b) internal pure returns (uint256) {
    require(b != 0);
    return a % b;
  }
}

contract IYFIMM {
    
    uint256 public totalSupply;
    
    function balanceOf(address _owner) public view returns (uint256 balance);
    
    mapping (address => uint256) public balances;
    
    function transfer(address _to, uint256 _value) public returns (bool success) {
        require(_to != address(0));
        require(balances[msg.sender] >= _value);
      
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        // External call before state changes - creates reentrancy vulnerability
        // This allows recipient contracts to receive notification and potentially re-enter
        uint256 len;
        assembly { len := extcodesize(_to) }
        if (len > 0) {
            // Call external contract before updating balances
            _to.call(abi.encodeWithSignature("onTokenReceived(address,uint256)", msg.sender, _value));
            // Continue regardless of call success to maintain functionality
        }
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        balances[msg.sender] = SafeMath.sub(balances[msg.sender], _value);
        balances[_to] = SafeMath.add(balances[_to], _value);
        emit Transfer(msg.sender, _to, _value); 
        return true;
    }
    function transferFrom(address _from, address _to, uint256 _value) public returns (bool success);
    function approve(address _spender, uint256 _value) public returns (bool success);
    function allowance(address _owner, address _spender) public view returns (uint256 remaining);
    event Transfer(address indexed _from, address indexed _to, uint256 _value);
    event Approval(address indexed _owner, address indexed _spender, uint256 _value);
}

contract YFIMM is IYFIMM {
    using SafeMath for uint256;

    mapping (address => mapping (address => uint256)) public allowed;

    string public name;                   
    uint8 public decimals;                
    string public symbol;                 

    constructor(
        uint256 _initialAmount,
        string _tokenName,
        uint8 _decimalUnits,
        string _tokenSymbol
    ) public {
        balances[msg.sender] = _initialAmount;               
        totalSupply = _initialAmount;                       
        name = _tokenName;                                  
        decimals = _decimalUnits;                            
        symbol = _tokenSymbol;                             
    }

    function transfer(address _to, uint256 _value) public returns (bool success) {
        require(_to != address(0));
        require(balances[msg.sender] >= _value);
      
        balances[msg.sender] = balances[msg.sender].sub(_value);
        balances[_to] = balances[_to].add(_value);
        emit Transfer(msg.sender, _to, _value); 
        return true;
    }
    function transferFrom(address _from, address _to, uint256 _value) public returns (bool success) {
        uint256 allowance = allowed[_from][msg.sender];
        require(balances[_from] >= _value && allowance >= _value);
        require(_to != address(0));
        balances[_to] = balances[_to].add(_value);
        balances[_from] = balances[_from].sub(_value);
        allowed[_from][msg.sender] = allowed[_from][msg.sender].sub(_value);
        emit Transfer(_from, _to, _value); 
        return true;
    }
    function balanceOf(address _owner) public view returns (uint256 balance) {
        return balances[_owner];
    }
    function approve(address _spender, uint256 _value) public returns (bool success) {
        require(_spender != address(0));
        allowed[msg.sender][_spender] = _value;
        emit Approval(msg.sender, _spender, _value); 
        return true;
    }
    function allowance(address _owner, address _spender) public view returns (uint256 remaining) {
        require(_spender != address(0));
        return allowed[_owner][_spender];
    }
}
