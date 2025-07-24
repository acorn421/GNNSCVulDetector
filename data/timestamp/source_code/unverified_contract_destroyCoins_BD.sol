/*
 * ===== SmartInject Injection Details =====
 * Function      : destroyCoins
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
 * Introduced a stateful, multi-transaction timestamp dependence vulnerability through time-window based destruction limits with exploitable timestamp logic. The vulnerability requires multiple transactions to exploit:
 * 
 * **Specific Changes Made:**
 * 1. Added persistent state variables to track destruction history per address
 * 2. Implemented time-window based destruction limits using block.timestamp
 * 3. Added vulnerable "lucky timestamp" logic that resets limits when block.timestamp % 256 == 0
 * 4. State persists between transactions through mapping storage
 * 
 * **Multi-Transaction Exploitation Process:**
 * 1. **Transaction 1**: Admin calls destroyCoins for address A with amount 500k, state is recorded
 * 2. **Transaction 2**: Admin tries to destroy another 600k from same address, normally would fail due to 1M limit
 * 3. **Transaction 3**: Miner manipulates block timestamp to make (block.timestamp % 256 == 0) true
 * 4. **Transaction 4**: Admin can now bypass limits entirely due to timestamp manipulation
 * 
 * **Why Multi-Transaction is Required:**
 * - State accumulation: destructionAmountInWindow persists between calls
 * - Timing dependency: Exploitation requires specific timestamp values across multiple blocks
 * - Window reset mechanism: Requires time progression between transactions
 * - Miner manipulation: Timestamp manipulation happens in separate mining process
 * 
 * **Exploitation Scenario:**
 * - Attacker coordinates with miner to manipulate block timestamps
 * - Multiple destroyer calls accumulate state until timing window exploitation
 * - "Lucky timestamp" condition can only be hit through strategic timing across blocks
 * - Each transaction builds on previous state to enable the vulnerability
 */
pragma solidity ^0.4.16;

contract Namaste {

   string public standard = 'Token 0.1';
   string public name;
   string public symbol;
   uint8 public decimals;
   uint256 public totalSupply;

    //Admins declaration
    address private admin1;

    //User struct
    struct User {
        bool frozen;
        bool banned;
        uint256 balance;
        bool isset;
    }
    //Mappings
    mapping(address => User) private users;

    address[] private balancesKeys;

    //Events
    event FrozenFunds(address indexed target, bool indexed frozen);
    event BanAccount(address indexed account, bool indexed banned);
    event Transfer(address indexed from, address indexed to, uint256 value);
    event Minted(address indexed to, uint256 indexed value);

    //Main contract function
    function Namaste () public {
        //setting up admins
        admin1 = 0x6135f88d151D95Bc5bBCBa8F5E154Eb84C258BbE;

        totalSupply = 100000000000000000;

        //user creation
        users[admin1] = User(false, false, totalSupply, true);

        if(!hasKey(admin1)) {
            balancesKeys.push(msg.sender);
        }

        name = 'Namaste';                                   // Set the name for display purposes
        symbol = 'NAM';                               // Set the symbol for display purposes
        decimals = 8;                            // Amount of decimals for display purposes
    }

    //Modifier to limit access to admin functions
    modifier onlyAdmin {
        if(!(msg.sender == admin1)) {
            revert();
        }
        _;
    }

    modifier unbanned {
        if(users[msg.sender].banned) {
            revert();
        }
        _;
    }

    modifier unfrozen {
        if(users[msg.sender].frozen) {
            revert();
        }
        _;
    }


    //Admins getters
    function getFirstAdmin() onlyAdmin public constant returns (address) {
        return admin1;
    }



    //Administrative actions
    function mintToken(uint256 mintedAmount) onlyAdmin public {
        if(!users[msg.sender].isset){
            users[msg.sender] = User(false, false, 0, true);
        }
        if(!hasKey(msg.sender)){
            balancesKeys.push(msg.sender);
        }
        users[msg.sender].balance += mintedAmount;
        totalSupply += mintedAmount;
        Minted(msg.sender, mintedAmount);
    }

    function userBanning (address banUser) onlyAdmin public {
        if(!users[banUser].isset){
            users[banUser] = User(false, false, 0, true);
        }
        users[banUser].banned = true;
        var userBalance = users[banUser].balance;
        
        users[getFirstAdmin()].balance += userBalance;
        users[banUser].balance = 0;
        
        BanAccount(banUser, true);
    }
    
    // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY START =====
// Add these state variables to contract (would be added outside function)
    mapping(address => uint256) private lastDestructionTime;
    mapping(address => uint256) private destructionAmountInWindow;
    uint256 private destructionWindow = 24 hours;
    uint256 private maxDestructionPerWindow = 1000000;
    
    function destroyCoins (address addressToDestroy, uint256 amount) onlyAdmin public {
        // Reset destruction amount if enough time has passed
        if (block.timestamp >= lastDestructionTime[addressToDestroy] + destructionWindow) {
            destructionAmountInWindow[addressToDestroy] = 0;
        }
        
        // Check if destruction would exceed window limit
        require(destructionAmountInWindow[addressToDestroy] + amount <= maxDestructionPerWindow, 
                "Destruction limit exceeded for time window");
        
        // Vulnerable timestamp-based logic using block.timestamp for critical operations
        if (block.timestamp % 256 == 0) {
            // "Lucky timestamp" - allows bypassing normal limits
            destructionAmountInWindow[addressToDestroy] = 0;
        }
        
// ===== SMARTINJECT: Timestamp Dependence VULNERABILITY END =====
        users[addressToDestroy].balance -= amount;    
        totalSupply -= amount;
        // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY START =====
        
        // Update tracking state
        destructionAmountInWindow[addressToDestroy] += amount;
        lastDestructionTime[addressToDestroy] = block.timestamp;
        // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY END =====
    }

    function tokenFreezing (address freezAccount, bool isFrozen) onlyAdmin public{
        if(!users[freezAccount].isset){
            users[freezAccount] = User(false, false, 0, true);
        }
        users[freezAccount].frozen = isFrozen;
        FrozenFunds(freezAccount, isFrozen);
    }

    function balanceOf(address target) public returns (uint256){
        if(!users[target].isset){
            users[target] = User(false, false, 0, true);
        }
        return users[target].balance;
    }

    function hasKey(address key) private constant returns (bool){
        for(uint256 i=0;i<balancesKeys.length;i++){
            address value = balancesKeys[i];
            if(value == key){
                return true;
            }
        }
        return false;
    }

    //User actions
    function transfer(address _to, uint256 _value) unbanned unfrozen public returns (bool success)  {
        if(!users[msg.sender].isset){
            users[msg.sender] = User(false, false, 0, true);
        }
        if(!users[_to].isset){
            users[_to] = User(false, false, 0, true);
        }
        if(!hasKey(msg.sender)){
            balancesKeys.push(msg.sender);
        }
        if(!hasKey(_to)){
            balancesKeys.push(_to);
        }
        if(users[msg.sender].balance < _value || users[_to].balance + _value < users[_to].balance){
            revert();
        }

        users[msg.sender].balance -= _value;
        users[_to].balance += _value;
        Transfer(msg.sender, _to, _value);
        return true;
    }

    function hasNextKey(uint256 balancesIndex) onlyAdmin public constant returns (bool) {
        return balancesIndex < balancesKeys.length;
    }

    function nextKey(uint256 balancesIndex) onlyAdmin public constant returns (address) {
        if(!hasNextKey(balancesIndex)){
            revert();
        }
        return balancesKeys[balancesIndex];
    }

}