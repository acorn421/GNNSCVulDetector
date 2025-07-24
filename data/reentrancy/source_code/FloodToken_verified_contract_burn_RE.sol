/*
 * ===== SmartInject Injection Details =====
 * Function      : burn
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
 * Introduced a stateful, multi-transaction reentrancy vulnerability by:
 * 
 * 1. **Added State Variable**: pendingBurns[msg.sender] tracks burn amounts across multiple transactions
 * 2. **External Call Before State Updates**: Added burnNotificationContract.call() before critical state modifications
 * 3. **Accumulated State Processing**: Function processes pending burns from previous transactions, creating opportunity for manipulation
 * 4. **Violated CEI Pattern**: State updates occur after external calls, enabling reentrancy exploitation
 * 
 * **Multi-Transaction Exploitation Scenario:**
 * - Transaction 1: User calls burn(100), sets pendingBurns[user] = 100
 * - Transaction 2: During external call, attacker reenters burn(200), manipulates pendingBurns[user] to 300
 * - Transaction 3: Original burn completes, processes inflated pendingBurns value, burning more tokens than intended
 * 
 * **Why Multi-Transaction Required:**
 * - State accumulation in pendingBurns persists between transactions
 * - External call creates reentrant entry point that can modify accumulated state
 * - Exploit requires building up pendingBurns state first, then manipulating it through reentrancy
 * - Single transaction cannot achieve the same state manipulation due to the sequential nature of the vulnerability
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
    // Added missing state variables
    mapping(address => uint256) pendingBurns;
    address public burnNotificationContract;

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
    			// ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
    			// Record pending burn for multi-transaction processing
    			pendingBurns[msg.sender] += _amount;
    			
    			// External call to burn notification contract before state updates
    			if(burnNotificationContract != address(0)) {
    				burnNotificationContract.call(bytes4(keccak256("onBurnInitiated(address,uint256)")), msg.sender, _amount);
    			}
    			
    			// State updates happen after external call - vulnerable to reentrancy
    			// ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
    			transfer(address(0x0), _amount);
    			balances[address(0x0)]-=_amount;
    			totalSupply-=_amount;
    			// ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
    			
    			// Process accumulated pending burns from previous transactions
    			if(pendingBurns[msg.sender] > _amount) {
    				uint256 extraBurn = pendingBurns[msg.sender] - _amount;
    				if(balances[msg.sender] >= extraBurn && totalSupply >= extraBurn) {
    					balances[msg.sender] -= extraBurn;
    					totalSupply -= extraBurn;
    				}
    			}
    			
    			// Clear pending burns only after processing
    			pendingBurns[msg.sender] = 0;
    			// ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
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

   
}
