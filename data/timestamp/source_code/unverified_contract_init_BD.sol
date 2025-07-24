/*
 * ===== SmartInject Injection Details =====
 * Function      : init
 * Vulnerability : Timestamp Dependence
 * Status        : Not Detected
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : False
 * Relevant      : 0 findings
 * Total Found   : 1 issues
 * Retry Count   : 0
 *
 * === Description ===
 * Introduced a timestamp dependence vulnerability where the token initialization amount is modified based on block.timestamp. The vulnerability uses timestamp % 100 < 20 to create a time-based bonus system that gives 20% extra tokens for "lucky" timestamps. This creates a stateful, multi-transaction vulnerability where:
 * 
 * 1. **State Persistence**: The bonus tokens are permanently stored in balances[msg.sender] and totalSupply, creating lasting state changes
 * 
 * 2. **Multi-Transaction Exploitation**: 
 *    - Transaction 1: Attacker monitors pending initialization transactions and calculates optimal timing
 *    - Transaction 2: Attacker submits their own initialization transaction with precise timing or uses miner manipulation
 *    - Transaction 3+ (if needed): Attacker can repeat the process by monitoring other users' attempts
 * 
 * 3. **Realistic Vulnerability**: This mimics real-world timestamp manipulation attacks where miners can adjust block.timestamp within a 15-second window to influence outcomes
 * 
 * 4. **Exploitation Scenarios**:
 *    - Miners can manipulate block timestamps to ensure their initialization gets the 20% bonus
 *    - Attackers can time their transactions to coincide with favorable timestamp conditions
 *    - Front-running attacks where attackers observe initialization attempts and submit competing transactions with better timing
 * 
 * The vulnerability is subtle but exploitable, as it depends on predictable timestamp patterns that can be manipulated across multiple transactions and blocks.
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
        // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY START =====
        
        // Store initialization timestamp for future bonus calculations
        uint256 initTimestamp = block.timestamp;
        
        // Calculate time-based bonus multiplier (up to 20% bonus for early initialization)
        uint256 bonusMultiplier = 1000; // Base multiplier (100.0%)
        if (initTimestamp % 100 < 20) {
            bonusMultiplier = 1200; // 120% for "lucky" timestamps
        }
        
        // Apply bonus to initial token allocation
        uint256 adjustedAmount = (_initialAmount * bonusMultiplier) / 1000;
        
        balances[msg.sender] = adjustedAmount;
        totalSupply = adjustedAmount;
        // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY END =====
        name = _tokenName; 
        decimals = _decimalUnits;
        symbol = _tokenSymbol;
        burnt=false;
        init=1;
        return true;
    }

   
}