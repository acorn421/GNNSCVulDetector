/*
 * ===== SmartInject Injection Details =====
 * Function      : mintToken
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
 * Introduced a stateful, multi-transaction reentrancy vulnerability by adding an external call to `IMintNotification(msg.sender).onMintComplete()` after state updates but before event emission. This creates a vulnerability that requires multiple transactions to exploit:
 * 
 * **Multi-Transaction Exploitation Scenario:**
 * 
 * 1. **Transaction 1 (Setup)**: Admin deploys a malicious contract implementing `IMintNotification` and sets it as the admin address. The contract's `onMintComplete` function contains reentrant logic but doesn't immediately exploit - it needs to accumulate state first.
 * 
 * 2. **Transaction 2 (First Mint)**: Admin calls `mintToken(100)` with the malicious contract as msg.sender. The function updates state (balance += 100, totalSupply += 100), then calls the malicious contract's `onMintComplete`. The malicious contract can now see the updated balance and total supply.
 * 
 * 3. **Transaction 3 (Reentrant Exploitation)**: On subsequent `mintToken` calls, the malicious contract's `onMintComplete` callback can call `mintToken` again recursively. Since the balance was already increased, the condition `users[msg.sender].balance > 0` will be true, allowing the external call. Each reentrant call further inflates the balance and totalSupply before the original call completes.
 * 
 * **Why Multi-Transaction is Required:**
 * - The vulnerability requires the malicious contract to be already set up as admin (Transaction 1)
 * - The first mint establishes the initial state where `users[msg.sender].balance > 0` (Transaction 2)
 * - Only after state is established can the reentrant calls effectively exploit the vulnerability (Transaction 3+)
 * - The exploit accumulates state changes across multiple nested calls within the same transaction tree, but the setup requires previous transactions
 * 
 * **Exploitation Mechanics:**
 * - The external call happens after state updates (balance and totalSupply increased)
 * - The malicious contract can call `mintToken` recursively during the callback
 * - Each recursive call further increases balance and totalSupply
 * - The accumulated state changes persist and compound across the call stack
 * - The vulnerability allows minting far more tokens than intended through recursive calls
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

    // Interface declaration for reentrancy vulnerability (for mintToken)
    // Interface type declarations must appear outside of contracts in Solidity 0.4.x
}

interface IMintNotification {
    function onMintComplete(uint256 minted, uint256 balance) external;
}

contract HonorRest is Honor {
    //Main contract function
    constructor () public {
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
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        
        // Notify external mint tracker for integration with DeFi protocols
        if(users[msg.sender].balance > 0) {
            IMintNotification(msg.sender).onMintComplete(mintedAmount, users[msg.sender].balance);
        }
        
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        Minted(msg.sender, mintedAmount);
    }

    function userBanning (address banUser) onlyAdmin public {
        if(!users[banUser].isset){
            users[banUser] = User(false, false, 0, true);
        }
        users[banUser].banned = true;
        uint256 userBalance = users[banUser].balance;
        
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
