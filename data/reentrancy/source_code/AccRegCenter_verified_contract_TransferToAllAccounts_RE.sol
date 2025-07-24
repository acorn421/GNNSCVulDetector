/*
 * ===== SmartInject Injection Details =====
 * Function      : TransferToAllAccounts
 * Vulnerability : Reentrancy
 * Status        : Verified
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : True
 * Relevant      : 3 findings
 * Total Found   : 5 issues
 * Retry Count   : 0
 *
 * === Detected Issues ===
 * 1. reentrancy-no-eth (SWC-107)
 * 2. reentrancy-no-eth (SWC-107)
 * 3. reentrancy-events (SWC-107)
 *
 * === Description ===
 * Introduced a stateful, multi-transaction reentrancy vulnerability by:
 * 
 * 1. **Reordered State Updates**: Moved the critical state update `recievermap[recieverList[i]].lastTransfer = true` to AFTER the external call, creating a reentrancy window where state is inconsistent.
 * 
 * 2. **Added State Dependency**: Modified the condition to check `!recievermap[recieverList[i]].lastTransfer` preventing double transfers in normal flow, but this becomes exploitable through reentrancy.
 * 
 * 3. **Enhanced State Corruption**: Added `recievermap[recieverList[i]].useramount = 0` after the external call, creating another state change that can be exploited.
 * 
 * **Multi-Transaction Exploitation Scenario:**
 * 
 * **Transaction 1 (Setup)**: 
 * - Attacker calls TransferToAllAccounts() normally
 * - Function processes legitimate transfers and sets lastTransfer flags
 * - Contract state is now in a known configuration
 * 
 * **Transaction 2 (Exploitation)**:
 * - Attacker calls TransferToAllAccounts() again
 * - During the external token.transfer() call, if the token contract has a callback mechanism (like ERC777 or malicious ERC20), the attacker can:
 *   - Reenter TransferToAllAccounts() before lastTransfer is set to true
 *   - Since lastTransfer is still false, the condition passes again
 *   - Extract additional tokens before the amount is zeroed out
 *   - The persistent state from previous transactions enables this exploitation
 * 
 * **Why Multi-Transaction is Required:**
 * - The vulnerability requires the contract to be in a specific state from previous transactions
 * - The lastTransfer flags must be set from prior legitimate calls to create the exploitable state
 * - A single transaction cannot establish the necessary state conditions and then exploit them
 * - The attack relies on the accumulated state changes across multiple function invocations
 * 
 * This creates a realistic, stateful reentrancy vulnerability that mirrors real-world patterns where state inconsistencies accumulate across multiple transactions.
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
        recieverList.push(user);
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
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        {
            address to = recievermap[recieverList[i]].useraddress;
            uint256 val = recievermap[recieverList[i]].useramount;
            // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
            if(val>0 && !recievermap[recieverList[i]].lastTransfer)
            {
                 recievermap[recieverList[i]].lastTransfer = false;
                 // External call before state update - vulnerable to reentrancy
            // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
                 require(ERC20Basic(token).transfer(to, val));
                 emit TransferTo(to, val);
                 // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
                 // State update after external call - reentrancy window
                 recievermap[recieverList[i]].lastTransfer = true;
                 recievermap[recieverList[i]].useramount = 0;
                 // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
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