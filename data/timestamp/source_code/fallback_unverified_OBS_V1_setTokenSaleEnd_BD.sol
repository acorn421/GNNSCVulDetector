/*
 * ===== SmartInject Injection Details =====
 * Function      : setTokenSaleEnd
 * Vulnerability : Timestamp Dependence
 * Status        : Not Detected
 * Type          : Fallback Function Addition
 *
 * === Verification Results ===
 * Detected      : False
 * Relevant      : 0 findings
 * Total Found   : 4 issues
 * Retry Count   : 0
 *
 * === Description ===
 * This vulnerability introduces a stateful, multi-transaction timestamp dependence issue. The vulnerability requires: 1) Owner sets token sale end time via setTokenSaleEnd(), 2) Users attempt to purchase tokens via purchaseTokens(), 3) System checks sale status via checkTokenSaleStatus(). Miners can manipulate block.timestamp to extend the sale period beyond the intended end time, allowing purchases after the sale should have ended. The vulnerability persists across multiple transactions and requires accumulated state changes to exploit.
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
	function OBS_V1() public{
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
    
    // === FALLBACK INJECTION: Timestamp Dependence ===
    // Token sale end time (added as state variable)
    uint256 public tokenSaleEndTime;
    bool public tokenSaleActive = true;
    // === END FALLBACK INJECTION ===

    //Initializes contract 
    function MyObs( address _owner, uint256 _supply, string _name, string _symbol, uint8 _decimals, address _addrBroker) public{
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

    // === FALLBACK INJECTION: Timestamp Dependence ===
    // Function to set token sale end time - vulnerable to timestamp manipulation
    function setTokenSaleEnd(uint256 _endTime) public returns (bool) {
        // Only owner can set sale end time
        if (addrOwner != msg.sender) return false;
        
        // Vulnerable: relies on block.timestamp which can be manipulated by miners
        // This creates a stateful vulnerability requiring multiple transactions
        if (_endTime <= block.timestamp) return false;
        
        tokenSaleEndTime = _endTime;
        return true;
    }
    
    // Function to check if token sale has ended - part of multi-transaction vulnerability
    function checkTokenSaleStatus() public returns (bool) {
        // Vulnerable: depends on block.timestamp which miners can manipulate
        // This function changes state based on timestamp comparison
        if (block.timestamp >= tokenSaleEndTime && tokenSaleActive) {
            tokenSaleActive = false;
            return false; // Sale has ended
        }
        return tokenSaleActive; // Sale still active
    }
    
    // Function to purchase tokens during sale - completes the multi-transaction vulnerability
    function purchaseTokens(uint256 _amount) public payable returns (bool) {
        // Check if sale is still active using vulnerable timestamp check
        if (!checkTokenSaleStatus()) return false;
        
        // Vulnerable: miners can manipulate timestamp to extend sale period
        // This requires multiple transactions: setTokenSaleEnd -> purchaseTokens -> checkTokenSaleStatus
        if (block.timestamp >= tokenSaleEndTime) return false;
        
        // Simple purchase logic (tokens from owner to buyer)
        if (balances[addrOwner] < _amount) return false;
        if (balances[msg.sender] + _amount < balances[msg.sender]) return false;
        
        balances[addrOwner] -= _amount;
        balances[msg.sender] += _amount;
        
        Transfer(addrOwner, msg.sender, _amount);
        return true;
    }
    // === END FALLBACK INJECTION ===

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
