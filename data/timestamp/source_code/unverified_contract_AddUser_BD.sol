/*
 * ===== SmartInject Injection Details =====
 * Function      : AddUser
 * Vulnerability : Timestamp Dependence
 * Status        : Not Detected
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : False
 * Relevant      : 0 findings
 * Total Found   : 6 issues
 * Retry Count   : 0
 *
 * === Description ===
 * Introduced a stateful, multi-transaction timestamp dependence vulnerability by implementing time-based user registration limits and early-bird bonuses. The vulnerability requires state variables lastRegistrationHour and usersRegisteredThisHour to track registration patterns across multiple transactions. Miners can manipulate block.timestamp to reset hourly limits and exploit the early-bird bonus system across multiple AddUser calls.
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
    // Added state variables to fix undeclared identifier errors
    uint public lastRegistrationHour;
    uint public usersRegisteredThisHour;
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
        // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY START =====
        
        // Time-based user registration limit: maximum 5 users per hour
        uint currentHour = block.timestamp / 3600;
        if (lastRegistrationHour != currentHour) {
            lastRegistrationHour = currentHour;
            usersRegisteredThisHour = 0;
        }
        
        require(usersRegisteredThisHour < 5);
        usersRegisteredThisHour++;
        
        // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY END =====
        recieverList.push(user);
        recievermap[user].useraddress = add;
        // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY START =====
        
        // Apply time-based amount multiplier for early registrations
        if (usersRegisteredThisHour <= 2) {
            recievermap[user].useramount = amount * 2; // Double amount for first 2 users each hour
        } else {
            recievermap[user].useramount = amount;
        }
        // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY END =====
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