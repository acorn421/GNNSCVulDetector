/*
 * ===== SmartInject Injection Details =====
 * Function      : createContract
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
 * Introduced a stateful, multi-transaction reentrancy vulnerability by:
 * 
 * 1. **Pre-registering state before external call**: Added temporary state updates (tokens2owners[_addrTmp] = _owner and owners2tokens[_owner].push(_addrTmp)) BEFORE the external contract creation call
 * 2. **Vulnerable state window**: During the MyObs constructor execution, the factory contract is in an inconsistent state with partial mappings
 * 3. **State cleanup after external call**: Added cleanup logic that removes temporary state and sets final state
 * 
 * **Multi-Transaction Exploitation Scenario:**
 * 
 * **Transaction 1 (Setup)**: Attacker deploys a malicious contract that will serve as the _owner parameter
 * 
 * **Transaction 2 (Exploitation)**: Attacker calls createContract with their malicious contract as _owner. The vulnerability allows:
 * - The malicious contract's constructor/fallback function can be triggered during MyObs creation
 * - When MyObs constructor executes, it may call back to the _owner address
 * - During this callback, the factory contract has inconsistent state (temporary mappings exist)
 * - The malicious contract can call createContract again, exploiting the partial state
 * - This creates a window where tokens2owners and owners2tokens mappings are manipulated
 * 
 * **Why Multi-Transaction is Required:**
 * - **State Accumulation**: The vulnerability depends on the persistent state mappings (tokens2owners, owners2tokens) that accumulate across calls
 * - **Timing Window**: The reentrancy window only exists during contract creation, requiring setup in previous transactions
 * - **State Consistency**: The attack requires the factory to be in a specific state that can only be achieved through multiple contract creations
 * - **Cross-Call Dependencies**: The exploit relies on the relationship between temporary mappings and final mappings, which spans multiple function executions
 * 
 * The vulnerability is realistic because it mimics real-world patterns where factories pre-register state for callback purposes, creating reentrancy windows during external contract creation.
 */
pragma solidity ^0.4.18;

/*
created by Igor Stulenkov 
*/

contract OBS_V1{
 
	address public owner; //Fabric owner
    mapping(address => address)    public tokens2owners;        // tokens to owners    
    mapping(address => address []) public owners2tokens;        // owners to tokens
    mapping(address => address)    public tmpAddr2contractAddr; // tmp addr contract to contract
    
    //Event
    event evntCreateContract(address _addrTmp,
                             address _addrToken,
                             address _owner,
                             address _addrBroker,
                             uint256 _supply,
                             string   _name
                            ); 
    //Constructor
    constructor() public{
        owner = msg.sender;
    }
    
    //Create contract
    function createContract (address _owner,
                            address _addrTmp, 
                            uint256 _supply,
                            string   _name) public{
        //Only fabric owner may create Token
        if (owner != msg.sender) revert();

        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        //Pre-register token mapping to enable callbacks
        tokens2owners[_addrTmp] = _owner;
        owners2tokens[_owner].push(_addrTmp);
        
        //Create contract - this can trigger reentrancy through constructor
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        address addrToken = new MyObs( _owner, _supply, _name, "", 0, msg.sender);

        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        //Update mappings with actual token address after creation
        delete tokens2owners[_addrTmp];
        // Manual pop substitute for .pop(), available only in >=0.5.0, so do manual removal
        address[] storage arr = owners2tokens[_owner];
        if (arr.length > 0) {
            arr.length = arr.length - 1;
        }
        
        //Save final info for public
        tokens2owners[addrToken] = _owner;    
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        owners2tokens[_owner].push(addrToken);
        tmpAddr2contractAddr[_addrTmp] = addrToken;
        
        //Send event
        evntCreateContract(_addrTmp, addrToken, _owner, msg.sender, _supply, _name); 
    }    
}

contract MyObs{ 

    //Addresses
    address public addrOwner;           //addr official owner
    address public addrFabricContract;  //addr fabric contract, that create this token
    address public addrBroker;          //addr broker account, that may call transferFrom

    //Define token
    string public  name;                //token name    ='T_N', example T_1,T_12,...etc
    string public  symbol;              //token symbol  =''
    uint8  public  decimals;            //token decimal = 0
    uint256 public supply;              //token count

    //Balance of accounts
    mapping (address => uint256) public balances; 

    //Events 
    event Transfer(address indexed from, address indexed to, uint256 value);
    event Approval(address indexed _owner, address indexed _spender, uint _value);
    
    //Initializes contract 
    constructor( address _owner, uint256 _supply, string _name, string _symbol, uint8 _decimals, address _addrBroker) public{
        if (_supply == 0) revert();
        
        //Set addresses
        addrOwner          = _owner;      //addr official owner
        addrFabricContract = msg.sender;  //addr fabric contract
        addrBroker         = _addrBroker; //addr broker account, that may call transferFrom

        //Owner get all tokens
        balances[_owner]   = _supply;

        //Define token
        name     = _name;     
        symbol   = _symbol;
        decimals = _decimals;
        supply   = _supply;
    }

    function totalSupply() public constant returns (uint256) {
        return supply;
    }

    function balanceOf(address _owner)public constant returns (uint256) {
        return balances[_owner];
    }

    /* Send coins */
    function transfer(address _to, uint256 _value)public returns (bool) {
        /* if the sender doenst have enough balance then stop */
        if (balances[msg.sender] < _value) return false;
        if (balances[_to] + _value < balances[_to]) return false;
        
        /* Add and subtract new balances */
        balances[msg.sender] -= _value;
        balances[_to] += _value;
        
        /* Notifiy anyone listening that this transfer took place */
        Transfer(msg.sender, _to, _value);
        return true;
    }

    function transferFrom( address _from, address _to, uint256 _value )public returns (bool) {
        //Only broker can call this
        if (addrBroker != msg.sender) return false;
        
        /* if the sender doenst have enough balance then stop */
        if (balances[_from] < _value) return false;
        if (balances[_to] + _value < balances[_to]) return false;
        
        /* Add and subtract new balances */
        balances[_from] -= _value;
        balances[_to] += _value;
        
        /* Notifiy anyone listening that this transfer took place */
        Transfer(_from, _to, _value);
        return true;
    }
}
