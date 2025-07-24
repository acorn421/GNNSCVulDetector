/*
 * ===== SmartInject Injection Details =====
 * Function      : createContract
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
 * Introduced multiple timestamp-dependent vulnerabilities that require multi-transaction exploitation:
 * 
 * 1. **Per-Owner Cooldown System**: Added lastCreationTime mapping and creationCooldown to prevent rapid contract creation by the same owner. This creates a stateful vulnerability where the timing between transactions matters.
 * 
 * 2. **Time-Based Supply Limits**: Implemented "premium hours" (6 AM to 6 PM UTC) where higher token supply is allowed, using block.timestamp % 86400 for daily cycle calculation. This creates predictable timing windows.
 * 
 * 3. **Global Hourly Rate Limiting**: Added contractsInWindow mapping that tracks contract creation per hour using block.timestamp / 3600. This creates a shared state that affects all users.
 * 
 * **Multi-Transaction Exploitation Scenarios:**
 * 
 * 1. **Cooldown Bypass**: An attacker can manipulate block timestamps as a miner to bypass the cooldown period, requiring multiple transactions spaced according to the manipulated timestamps.
 * 
 * 2. **Premium Hours Exploitation**: Attackers can time their transactions to exploit the higher supply limits during "premium hours" or manipulate timestamps to artificially trigger these windows.
 * 
 * 3. **Rate Limit Gaming**: Multiple users can coordinate to consume the hourly rate limit, then a miner can manipulate timestamps to reset the hour window and bypass the limit.
 * 
 * **Required State Variables** (to be added to contract):
 * - mapping(address => uint256) public lastCreationTime;
 * - uint256 public creationCooldown = 1 hours;
 * - uint256 public baseMaxSupply = 1000000;
 * - mapping(uint256 => uint256) public contractsInWindow;
 * - uint256 public maxContractsPerWindow = 10;
 * 
 * The vulnerability requires multiple transactions because:
 * - State must be accumulated across calls (cooldown tracking, rate limiting)
 * - Timing between transactions becomes critical
 * - Global state affects all future transactions
 * - Exploitation requires coordinated timing across multiple blocks
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

    // ===== Added storage variables required by injected code =====
    mapping(address => uint256) public lastCreationTime; // tracks last creation timestamp per owner
    uint256 public creationCooldown = 1 hours;           // cooldown period per owner (default: 1 hour)
    uint256 public baseMaxSupply = 1000000;              // base max supply (example default)
    mapping(uint256 => uint256) public contractsInWindow; // global rate limiting per time window
    uint256 public maxContractsPerWindow = 100;          // max contracts per hour (example default)
    // ============================================================

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
// ===== SMARTINJECT: Timestamp Dependence VULNERABILITY START =====

        // Rate limiting: prevent spam creation with cooldown period
        if (lastCreationTime[_owner] > 0) {
            // Use block.timestamp for time-based access control
            require(block.timestamp >= lastCreationTime[_owner] + creationCooldown, "Cooldown period not met");
        }
        
        // Store creation timestamp for this owner
        lastCreationTime[_owner] = block.timestamp;
        
        // Enhanced supply validation based on time-sensitive factors
        uint256 maxSupplyAllowed = baseMaxSupply;
        
        // Time-based supply boost: allow higher supply during "premium hours"
        // This creates predictable timing windows that can be exploited
        if (block.timestamp % 86400 >= 21600 && block.timestamp % 86400 <= 64800) { // 6 AM to 6 PM UTC
            maxSupplyAllowed = baseMaxSupply * 2;
        }
        
        require(_supply <= maxSupplyAllowed, "Supply exceeds time-based limit");
// ===== SMARTINJECT: Timestamp Dependence VULNERABILITY END =====

        //Create contract
        address addrToken = new MyObs( _owner, _supply, _name, "", 0, msg.sender);

        //Save info for public
        tokens2owners[addrToken]       = _owner;    
        owners2tokens[_owner].push(addrToken);
        tmpAddr2contractAddr[_addrTmp] = addrToken;
        
        // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY START =====
        // Track total contracts created in current time window for global rate limiting
        uint256 currentWindow = block.timestamp / 3600; // 1-hour windows
        if (contractsInWindow[currentWindow] >= maxContractsPerWindow) {
            revert("Global rate limit exceeded for current hour");
        }
        contractsInWindow[currentWindow]++;
        
        // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY END =====
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
    constructor(address _owner, uint256 _supply, string _name, string _symbol, uint8 _decimals, address _addrBroker) public{
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