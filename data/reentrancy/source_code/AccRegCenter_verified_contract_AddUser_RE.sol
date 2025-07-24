/*
 * ===== SmartInject Injection Details =====
 * Function      : AddUser
 * Vulnerability : Reentrancy
 * Status        : Verified
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : True
 * Relevant      : 3 findings
 * Total Found   : 6 issues
 * Retry Count   : 0
 *
 * === Detected Issues ===
 * 1. reentrancy-no-eth (SWC-107)
 * 2. reentrancy-no-eth (SWC-107)
 * 3. reentrancy-no-eth (SWC-107)
 *
 * === Description ===
 * Introduced a stateful, multi-transaction reentrancy vulnerability by:
 * 
 * 1. **State Modification Before External Call**: Added user to recieverList before external call, creating partial state
 * 2. **External Call Insertion**: Added call to user's address for "registration notification" - this is the reentrancy entry point
 * 3. **Critical State Updates After External Call**: Moved the actual user data assignments (useraddress and useramount) to occur AFTER the external call
 * 
 * **Multi-Transaction Exploitation Scenario:**
 * 
 * **Transaction 1 (Setup):**
 * - Owner calls AddUser("alice", maliciousContract, 1000)
 * - require() check passes (address is 0)
 * - recieverList.push("alice") executes - STATE CHANGE 1
 * - External call to maliciousContract.onUserRegistered("alice")
 * - MaliciousContract can now call back into AccRegCenter
 * 
 * **Transaction 2 (Exploitation via Reentrancy):**
 * - During the external call, maliciousContract calls back to AddUser("alice", attackerAddress, 5000)
 * - The require() check now FAILS because "alice" is already in recieverList but recievermap["alice"].useraddress is still address(0)
 * - This creates an inconsistent state where user exists in list but not in mapping
 * 
 * **Transaction 3 (State Corruption):**
 * - After reentrancy, original AddUser continues and sets recievermap["alice"].useraddress = maliciousContract
 * - But the reentrant call may have manipulated other state or triggered additional operations
 * - Results in corrupted user registry with duplicate entries or inconsistent mappings
 * 
 * **Why Multi-Transaction Required:**
 * - The vulnerability exploits the time window between partial state updates
 * - Requires coordination between the initial AddUser call and the reentrant callback
 * - State inconsistencies persist across transaction boundaries
 * - Attack requires setting up malicious contract first, then triggering the vulnerable sequence
 */
pragma solidity ^0.4.23;

contract ERC20Basic {
  // events
  event Transfer(address indexed from, address indexed to, uint256 value);

  // public functions
  function totalSupply() public view returns (uint256);
  function balanceOf(address addr) public view returns (uint256);
  function transfer(address to, uint256 value) public returns (bool);
}

contract Ownable {

  // public variables
  address public owner;

  // internal variables

  // events
  event OwnershipTransferred(address indexed previousOwner, address indexed newOwner);

  // public functions
  constructor() public {
    owner = msg.sender;
  }

  modifier onlyOwner() {
    require(msg.sender == owner);
    _;
  }

  function transferOwnership(address newOwner) public onlyOwner {
    require(newOwner != address(0));
    emit OwnershipTransferred(owner, newOwner);
    owner = newOwner;
  }

  // internal functions
}

contract AccRegCenter  is Ownable {
    
    
    struct User {
        address useraddress;
        uint useramount;
        bool lastTransfer;
    }
    
    ERC20Basic public token;
  // events
    event TransferTo(address indexed to, uint256 value);
    event TransferToName(address indexed to,string name, uint256 value);
    mapping(string => User) recievermap ;
    
    string[] public recieverList ;
    
    constructor( ERC20Basic _token ) public {
        require(_token != address(0));
        token = _token;
    }
    
    function AddUser(string user,address add,uint amount) onlyOwner public {
        require(recievermap[user].useraddress == address(0));
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        
        // Add user to pending list first (state change before external call)
        recieverList.push(user);
        
        // External call to notify user about registration - VULNERABILITY POINT
        // This allows the user contract to call back into AccRegCenter
        if(add != address(0)) {
            bool success = add.call(bytes4(keccak256("onUserRegistered(string)")), user);
            // Continue regardless of call success
        }
        
        // Critical state updates happen AFTER external call - VULNERABILITY
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        recievermap[user].useraddress = add;
        recievermap[user].useramount = amount;
    }
    
    function SetAddress(string user,address add) onlyOwner public {
        require(recievermap[user].useraddress!= address(0));
        recievermap[user].useraddress = add;
    }
    
    function SetAmount(string user,uint amount) onlyOwner public {
        require(recievermap[user].useraddress!= address(0));
        recievermap[user].useramount = amount;
        
    }
    
    function GetUser(string key) public constant returns(address add,uint amount,bool lastTransfer)
    {
        add = recievermap[key].useraddress;
        lastTransfer = recievermap[key].lastTransfer;
        amount = recievermap[key].useramount;
    }
    
    function TransferToAllAccounts() onlyOwner public {
        for(uint i=0;i<recieverList.length;i++)
        {
            recievermap[recieverList[i]].lastTransfer = false;
            address to = recievermap[recieverList[i]].useraddress;
            uint256 val = recievermap[recieverList[i]].useramount;
            if(val>0)
            {
                 require(ERC20Basic(token).transfer(to, val));
                 emit TransferTo(to, val);
                 recievermap[recieverList[i]].lastTransfer = true;
            }
        }
    }
    
    function ResetAllAmount() onlyOwner public {
        for(uint i=0;i<recieverList.length;i++)
        {
            recievermap[recieverList[i]].useramount = 0;
        }
    }
    
    function transfer(address to,uint val) onlyOwner public {
        require(ERC20Basic(token).transfer(to, val));
        emit TransferTo(to, val);
        
    }
    
    function transfertoacc(string key,uint val) onlyOwner public {
        recievermap[key].lastTransfer = false;
        address to = recievermap[key].useraddress;
        require(ERC20Basic(token).transfer(to, val));
        emit TransferToName(to,key, val);
        recievermap[key].lastTransfer = true;
    }
}