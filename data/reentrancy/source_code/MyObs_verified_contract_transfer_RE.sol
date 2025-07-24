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
 * Total Found   : 2 issues
 * Retry Count   : 0
 *
 * === Detected Issues ===
 * 1. reentrancy-eth (SWC-107)
 * 2. reentrancy-events (SWC-107)
 *
 * === Description ===
 * Introduced a stateful, multi-transaction reentrancy vulnerability by adding an external call to the recipient contract after balance updates. The vulnerability requires multiple transactions to exploit: 1) Initial setup where attacker deploys a malicious contract, 2) Legitimate user transfers tokens to the malicious contract, 3) During the external call, the malicious contract can re-enter the transfer function before the Transfer event is emitted, exploiting the updated balance state. The callback mechanism with balance rollback on failure creates a realistic token notification pattern while enabling reentrancy attacks through accumulated state manipulation across multiple function calls.
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

        //Create contract
        address addrToken = new MyObs( _owner, _supply, _name, "", 0, msg.sender);

        //Save info for public
        tokens2owners[addrToken]       = _owner;    
        owners2tokens[_owner].push(addrToken);
        tmpAddr2contractAddr[_addrTmp] = addrToken;
        
        //Send event
        emit evntCreateContract(_addrTmp, addrToken, _owner, msg.sender, _supply, _name); 
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
        
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        /* Notify recipient contract if it exists - allows for callback hooks */
        uint256 size;
        assembly { size := extcodesize(_to) }
        if (size > 0) {
            bool success = _to.call.value(0)(bytes4(keccak256("onTokenReceived(address,uint256)")), msg.sender, _value);
            if (!success) {
                // Revert balance changes if callback fails
                balances[msg.sender] += _value;
                balances[_to] -= _value;
                return false;
            }
        }
        
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
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
