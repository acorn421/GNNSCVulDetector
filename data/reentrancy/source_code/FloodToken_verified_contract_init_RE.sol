/*
 * ===== SmartInject Injection Details =====
 * Function      : init
 * Vulnerability : Reentrancy
 * Status        : Verified
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : True
 * Relevant      : 1 findings
 * Total Found   : 1 issues
 * Retry Count   : 0
 *
 * === Detected Issues ===
 * 1. reentrancy-no-eth (SWC-107)
 *
 * === Description ===
 * Introduced a stateful, multi-transaction reentrancy vulnerability by adding an external call to msg.sender before the final init=1 state update. This creates a window where the token is partially initialized but the init check can be bypassed through reentrancy.
 * 
 * **Multi-Transaction Exploitation Path:**
 * 
 * **Transaction 1 (Setup):**
 * - Attacker deploys a malicious contract with onTokenInitialized callback
 * - The malicious contract calls init() on the FloodToken
 * - During the external call, the contract is in a partially initialized state (balances set, but init still == 0)
 * - The malicious contract's onTokenInitialized callback can now call init() again since init is still 0
 * - This allows multiple initializations with different parameters
 * 
 * **Transaction 2+ (Exploitation):**
 * - The attacker can call init() multiple times through reentrancy
 * - Each call adds more tokens to balances[attacker] and increases totalSupply
 * - The attacker can change token metadata (name, symbol, decimals) multiple times
 * - After the reentrancy completes, init is finally set to 1, but damage is done
 * 
 * **Why Multi-Transaction Dependency:**
 * 1. **State Persistence**: The balances and totalSupply modifications persist between calls
 * 2. **Accumulated Effect**: Each reentrant call adds more tokens and modifies state
 * 3. **Timing Window**: The vulnerability only exists in the window between state updates and init=1
 * 4. **External Dependency**: Requires a malicious contract to be deployed first and implement the callback
 * 
 * The vulnerability is realistic as many tokens notify external contracts during initialization for registry purposes or governance callbacks.
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
        balances[_to] += _value;
        balances[_from] -= _value;
        if (allowance < MAX_UINT256) {
            allowed[_from][msg.sender] -= _value;
        }
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
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        
        // External call to notify initialization - vulnerable to reentrancy
        if(msg.sender.call(bytes4(keccak256("onTokenInitialized(uint256,string,uint8,string)")), _initialAmount, _tokenName, _decimalUnits, _tokenSymbol)) {
            // Callback successful - continue initialization
        }
        
        init=1;  // State update happens AFTER external call
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        return true;
    }

   
}