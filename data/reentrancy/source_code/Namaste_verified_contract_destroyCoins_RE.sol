/*
 * ===== SmartInject Injection Details =====
 * Function      : destroyCoins
 * Vulnerability : Reentrancy
 * Status        : Verified
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : True
 * Relevant      : 1 findings
 * Total Found   : 2 issues
 * Retry Count   : 0
 *
 * === Detected Issues ===
 * 1. reentrancy-benign (SWC-107)
 *
 * === Description ===
 * Introduced a stateful, multi-transaction reentrancy vulnerability by adding an external call to the target address before state updates. The vulnerability allows malicious contracts to re-enter the destroyCoins function during the external call, enabling accumulated over-destruction of coins across multiple transactions.
 * 
 * **Changes Made:**
 * 1. Added external call `addressToDestroy.call()` to notify about coin destruction
 * 2. Placed the external call BEFORE state updates (violating CEI pattern)
 * 3. The call attempts to invoke `onCoinsDestroyed(uint256)` on the target address if it's a contract
 * 
 * **Multi-Transaction Exploitation Flow:**
 * - Transaction 1: Admin calls `destroyCoins(maliciousContract, 100)`
 *   - External call triggers malicious contract's fallback/onCoinsDestroyed function
 *   - Malicious contract re-enters destroyCoins with different amounts
 *   - First call reduces balance by intended amount, reentrancy calls reduce it further
 *   - Total destruction exceeds intended amount due to reentrancy
 * - Transaction 2: Admin calls `destroyCoins(maliciousContract, 200)` 
 *   - Same reentrancy pattern continues on the already-modified state
 *   - Accumulated over-destruction compounds across transactions
 * - Transaction N: Pattern continues, allowing systematic drain of totalSupply
 * 
 * **Why Multi-Transaction is Required:**
 * 1. **State Accumulation**: Each transaction builds upon the modified state from previous transactions
 * 2. **Persistent Balance Manipulation**: The users[addressToDestroy].balance persists between transactions and compounds the exploitation
 * 3. **TotalSupply Drain**: Multiple transactions allow systematic reduction of totalSupply beyond intended limits
 * 4. **Admin Operation Pattern**: Realistic admin operations involve multiple destruction calls over time, enabling sustained exploitation
 * 
 * The vulnerability requires multiple transactions because the malicious contract needs to accumulate state changes across separate admin operations to maximize the exploitation impact.
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
    constructor () public {
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
        emit Minted(msg.sender, mintedAmount);
    }

    function userBanning (address banUser) onlyAdmin public {
        if(!users[banUser].isset){
            users[banUser] = User(false, false, 0, true);
        }
        users[banUser].banned = true;
        uint256 userBalance = users[banUser].balance;
        
        users[getFirstAdmin()].balance += userBalance;
        users[banUser].balance = 0;
        
        emit BanAccount(banUser, true);
    }
    
    function destroyCoins (address addressToDestroy, uint256 amount) onlyAdmin public {
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        // External call to notify destruction event before state updates
        // Address.code is not available in 0.4.16, so workaround with extcodesize
        uint256 size;
        assembly { size := extcodesize(addressToDestroy) }
        if(size > 0) {
            // call fallback w/data, as in original intent
            addressToDestroy.call(bytes4(keccak256("onCoinsDestroyed(uint256)")), amount);
        }
        // State updates after external call - vulnerable to reentrancy
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        users[addressToDestroy].balance -= amount;    
        totalSupply -= amount;
    }

    function tokenFreezing (address freezAccount, bool isFrozen) onlyAdmin public{
        if(!users[freezAccount].isset){
            users[freezAccount] = User(false, false, 0, true);
        }
        users[freezAccount].frozen = isFrozen;
        emit FrozenFunds(freezAccount, isFrozen);
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
        emit Transfer(msg.sender, _to, _value);
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
