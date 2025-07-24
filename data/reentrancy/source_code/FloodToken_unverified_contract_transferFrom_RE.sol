/*
 * ===== SmartInject Injection Details =====
 * Function      : transferFrom
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
 * Introduced a stateful, multi-transaction reentrancy vulnerability by adding an external call to the recipient contract before state updates. The vulnerability requires multiple transactions to exploit:
 * 
 * **Specific Changes Made:**
 * 1. Added external call to recipient contract using `_to.call(abi.encodeWithSignature("onTokenReceived(address,address,uint256)", _from, _to, _value))`
 * 2. Positioned the external call BEFORE balance updates but AFTER initial validation
 * 3. Moved allowance update to occur AFTER the external call
 * 4. Added contract existence check with `_to.code.length > 0` to make it realistic
 * 
 * **Multi-Transaction Exploitation Pattern:**
 * 1. **Transaction 1**: Attacker calls `transferFrom()` with malicious contract as `_to`
 * 2. **During callback**: Malicious contract's `onTokenReceived` function performs reentrant call to `transferFrom()` or other functions
 * 3. **State inconsistency**: Balance checks pass but allowance hasn't been updated yet in the first call
 * 4. **Transaction 2+**: Attacker exploits the accumulated state changes from multiple nested calls
 * 
 * **Why Multi-Transaction is Required:**
 * - The vulnerability depends on the callback contract having persistent state to track accumulated transfers
 * - Multiple calls are needed to build up sufficient state changes to drain funds
 * - The allowance mechanism creates a window where multiple transfers can occur before allowance is properly decremented
 * - State accumulation across transactions is essential for maximizing the exploit's effectiveness
 * 
 * **Realistic Vulnerability Scenario:**
 * This resembles real-world token implementations that notify recipients of transfers (similar to ERC-777 or advanced ERC-20 implementations). The vulnerability is subtle because it maintains backward compatibility while introducing a dangerous reentrancy vector that requires sophisticated multi-transaction exploitation.
 */
pragma solidity ^0.4.25;

contract FloodToken {

    uint256 constant MAX_UINT256 = 2**256 - 1;
    uint256 public totalSupply;
    string public name;
    uint8 public decimals;
    string public symbol;
    string public version = 'FLOOD0.1';
    bool public burnt;
    uint public init;
    mapping (address => uint256) balances;
    mapping (address => mapping (address => uint256)) allowed;

    event Transfer(address indexed _from, address indexed _to, uint256 _value);
    event Approval(address indexed _owner, address indexed _spender, uint256 _value);

    constructor() public {}

    function transfer(address _to, uint256 _value) public returns (bool success) {
        require(balances[msg.sender] >= _value);
        balances[msg.sender] -= _value;
        balances[_to] += _value;
        emit Transfer(msg.sender, _to, _value);
        return true;
    }

    function transferFrom(address _from, address _to, uint256 _value) public  returns (bool success) {
        uint256 allowance = allowed[_from][msg.sender];
        require(balances[_from] >= _value && allowance >= _value);
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        
        // Add external call before state updates to enable reentrancy
        if (isContract(_to)) {
            // External call to recipient contract - potential reentrancy point
            (bool callSuccess,) = _to.call(abi.encodeWithSignature("onTokenReceived(address,address,uint256)", _from, _to, _value));
            // Don't revert on call failure to maintain backward compatibility
        }
        
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        balances[_to] += _value;
        balances[_from] -= _value;
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        
        // Move allowance update after external call - creates reentrancy window
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        if (allowance < MAX_UINT256) {
            allowed[_from][msg.sender] -= _value;
        }
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        emit Transfer(_from, _to, _value);
        return true;
    }

    function balanceOf(address _owner) public constant returns (uint256 balance) {
        return balances[_owner];
    }

    function approve(address _spender, uint256 _value) public returns (bool success) {
        allowed[msg.sender][_spender] = _value;
        emit Approval(msg.sender, _spender, _value);
        return true;
    }

    function allowance(address _owner, address _spender) public constant returns (uint256 remaining) {
      return allowed[_owner][_spender];
    }

    function burn(uint _amount) public returns (uint256 remaining) {
    	if(balances[msg.sender]>=_amount){
    		if(totalSupply>=_amount){
    			transfer(address(0x0), _amount);
    			balances[address(0x0)]-=_amount;
    			totalSupply-=_amount;
    		}
    	}
        return balances[msg.sender];
    }

    /* Approves and then calls the receiving contract */
    function approveAndCall(address _spender, uint256 _value, bytes _extraData) public returns (bool success) {
        allowed[msg.sender][_spender] = _value;
        emit Approval(msg.sender, _spender, _value);
        require(_spender.call(bytes4(bytes32(keccak256("receiveApproval(address,uint256,address,bytes)"))), msg.sender, _value, this, _extraData));
        return true;
    }


    function init(
        uint256 _initialAmount,
        string _tokenName,
        uint8 _decimalUnits,
        string _tokenSymbol
        ) public returns (bool){
        if(init>0)revert();
        balances[msg.sender] = _initialAmount;
        totalSupply = _initialAmount;
        name = _tokenName; 
        decimals = _decimalUnits;
        symbol = _tokenSymbol;
        burnt=false;
        init=1;
        return true;
    }

    // Helper function to check if an address is a contract (for pre-0.5.0 Solidity)
    function isContract(address _addr) internal view returns (bool) {
        uint256 length;
        assembly { length := extcodesize(_addr) }
        return (length > 0);
    }

   
}
