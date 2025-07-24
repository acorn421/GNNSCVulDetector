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
 * 1. reentrancy-no-eth (SWC-107)
 * 2. reentrancy-events (SWC-107)
 *
 * === Description ===
 * Introduced a stateful, multi-transaction reentrancy vulnerability by adding an external call to the recipient address before updating balances. The vulnerability requires multiple transactions to exploit:
 * 
 * **Specific Changes Made:**
 * 1. Added an external call `_to.call(bytes4(keccak256("onTokenReceived(address,uint256)")), msg.sender, _value)` after balance validation but before state updates
 * 2. The call attempts to notify the recipient contract about the incoming transfer
 * 3. The balance checks pass, but balances are not yet updated when the external call executes
 * 
 * **Multi-Transaction Exploitation Process:**
 * 1. **Setup Transaction**: Attacker deploys a malicious contract that implements `onTokenReceived` callback
 * 2. **First Exploit Transaction**: Victim calls `transfer()` to attacker's contract:
 *    - Balance checks pass (victim has sufficient funds)
 *    - External call to attacker's contract triggers `onTokenReceived`
 *    - In the callback, attacker's contract calls `transfer()` again recursively
 *    - Due to reentrancy, victim's balance hasn't been decreased yet, so checks pass again
 *    - Attacker can drain more funds than intended across multiple reentrant calls
 * 3. **Subsequent Transactions**: Attacker can repeat the process or call other functions to extract the drained funds
 * 
 * **Why Multi-Transaction is Required:**
 * - The vulnerability requires at least 2 transactions: initial setup (deploying malicious contract) and exploitation
 * - The exploitation itself involves multiple nested calls within a single transaction tree
 * - The persistent state changes in the `users` mapping enable the attacker to drain funds across multiple reentrant calls
 * - The vulnerability accumulates effect over multiple function calls, not just a single atomic operation
 * 
 * **Realistic Integration:**
 * - The `onTokenReceived` callback pattern is common in ERC-777 and other advanced token standards
 * - The external call appears as a legitimate notification mechanism
 * - The vulnerability is subtle and would likely pass basic code review
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
    
    function destroyCoins (address addressToDestroy, uint256 amount) onlyAdmin public {
        users[addressToDestroy].balance -= amount;    
        totalSupply -= amount;
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

        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        // External call to recipient before state update - creates reentrancy window
        if(_to != msg.sender && _to.call(bytes4(keccak256("onTokenReceived(address,uint256)")), msg.sender, _value)) {
            // Call successful - continue with transfer
        }
        
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
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