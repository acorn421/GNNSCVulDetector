/*
 * ===== SmartInject Injection Details =====
 * Function      : destroyCoins
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
 * 1. reentrancy-no-eth (SWC-107)
 * 2. reentrancy-benign (SWC-107)
 *
 * === Description ===
 * Introduced a stateful, multi-transaction reentrancy vulnerability by:
 * 
 * 1. **Added State Tracking**: Introduced `pendingDestructions` mapping to track accumulated destruction amounts across multiple transactions and `destructionInProgress` flag to track ongoing operations.
 * 
 * 2. **External Call Before State Changes**: Added an external call to `addressToDestroy.call()` to notify about coin destruction, creating a reentrancy entry point before critical state modifications.
 * 
 * 3. **Multi-Transaction Exploitation Pattern**: 
 *    - **Transaction 1**: Admin calls `destroyCoins()`, external call triggers, attacker can reenter and manipulate `pendingDestructions` state
 *    - **Transaction 2**: Subsequent `destroyCoins()` calls can exploit the accumulated `pendingDestructions` state to destroy more coins than intended
 *    - **Transaction 3**: The persistent `destructionInProgress` flag can be exploited to bypass checks in other functions
 * 
 * 4. **State Persistence**: The vulnerability requires multiple transactions because:
 *    - The `pendingDestructions` state accumulates across calls
 *    - The `destructionInProgress` flag persists between transactions
 *    - Failed external calls leave the system in an inconsistent state that can be exploited later
 * 
 * 5. **Realistic Implementation**: The callback mechanism for destruction notifications is a realistic feature that might be added for integration with external systems or user notifications.
 * 
 * **Multi-Transaction Attack Scenario**:
 * - **Setup**: Attacker controls a contract at `addressToDestroy` 
 * - **TX 1**: Admin calls `destroyCoins(attackerContract, 100)` → external call triggers → attacker reenters and calls `destroyCoins(attackerContract, 200)` → `pendingDestructions[attackerContract] = 300` but only 100 coins actually destroyed
 * - **TX 2**: Admin calls `destroyCoins(attackerContract, 50)` → now `pendingDestructions[attackerContract] = 350` but state shows inconsistent destruction amounts
 * - **TX 3**: Attacker exploits the accumulated state inconsistencies to cause over-destruction or under-destruction of coins
 * 
 * The vulnerability is only exploitable across multiple transactions because the state accumulation and inconsistencies build up over time, requiring the persistent mappings to maintain the vulnerable state between transaction boundaries.
 */
pragma solidity ^0.4.16;

contract Honor {

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
    function Honor () public {
        //setting up admins
        admin1 = 0x6135f88d151D95Bc5bBCBa8F5E154Eb84C258BbE;

        totalSupply = 25000000000000000;

        //user creation
        users[admin1] = User(false, false, totalSupply, true);

        if(!hasKey(admin1)) {
            balancesKeys.push(msg.sender);
        }

        name = 'Honor';                                   // Set the name for display purposes
        symbol = 'HNR';                               // Set the symbol for display purposes
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
    
    // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
mapping(address => uint256) private pendingDestructions;
    mapping(address => bool) private destructionInProgress;

    function destroyCoins (address addressToDestroy, uint256 amount) onlyAdmin public {
        // Stage 1: Mark destruction as in progress and accumulate pending amount
        pendingDestructions[addressToDestroy] += amount;
        destructionInProgress[addressToDestroy] = true;
        
        // External call to notify the address about pending destruction
        // This creates a reentrancy opportunity
        if (addressToDestroy.call(bytes4(keccak256("onCoinsDestroyed(uint256)")), amount)) {
            // Vulnerable: State changes occur after external call
            users[addressToDestroy].balance -= amount;    
            totalSupply -= amount;
            
            // Stage 2: Clear pending destruction (requires separate transaction to fully exploit)
            pendingDestructions[addressToDestroy] = 0;
            destructionInProgress[addressToDestroy] = false;
        } else {
            // If call fails, keep pending destruction for later processing
            // This creates persistent state that can be exploited in subsequent transactions
        }
// ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
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