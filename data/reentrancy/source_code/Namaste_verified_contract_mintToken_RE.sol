/*
 * ===== SmartInject Injection Details =====
 * Function      : mintToken
 * Vulnerability : Reentrancy
 * Status        : Verified
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : True
 * Relevant      : 3 findings
 * Total Found   : 3 issues
 * Retry Count   : 0
 *
 * === Detected Issues ===
 * 1. reentrancy-eth (SWC-107)
 * 2. reentrancy-benign (SWC-107)
 * 3. reentrancy-events (SWC-107)
 *
 * === Description ===
 * Introduced a stateful, multi-transaction reentrancy vulnerability by adding an external call to `msg.sender.call()` before state updates. This creates a vulnerability where:
 * 
 * **Multi-Transaction Exploitation Path:**
 * 1. **Transaction 1**: Admin deploys a malicious contract that implements `onMintCallback()` and calls `mintToken()` with amount X
 * 2. **Transaction 2**: The malicious contract's `onMintCallback()` is triggered, which can re-enter `mintToken()` with a different amount Y
 * 3. **State Persistence**: The persistent state in `users` mapping and `totalSupply` allows the attack to accumulate across transactions
 * 
 * **Why Multi-Transaction is Required:**
 * - The admin modifier ensures only admin contracts can call this function
 * - An attacker must first establish an admin contract with callback functionality (Transaction 1)
 * - The callback mechanism then allows reentrancy in subsequent calls (Transaction 2+)
 * - The vulnerability exploits the fact that state changes occur AFTER the external call, violating the Checks-Effects-Interactions pattern
 * - Each reentrant call can mint additional tokens before the original call completes its state updates
 * 
 * **Realistic Exploitation:**
 * The malicious admin contract can:
 * - Receive the callback and immediately call `mintToken()` again with a larger amount
 * - Accumulate multiple mint operations before the original state updates complete
 * - Exploit the persistent state across multiple transaction sequences
 * 
 * This creates a realistic scenario where an admin contract with callback functionality can exploit reentrancy across multiple transactions to mint more tokens than intended.
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
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        
        // Add external call to notify mint callback before state updates
        // This creates a reentrancy vulnerability in multi-transaction scenarios
        if(msg.sender.call.value(0)(bytes4(keccak256("onMintCallback(uint256)")), mintedAmount)) {
            // Call succeeded, continue with normal flow
        }
        
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
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