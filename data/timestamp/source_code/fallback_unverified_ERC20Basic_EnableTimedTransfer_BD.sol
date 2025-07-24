/*
 * ===== SmartInject Injection Details =====
 * Function      : EnableTimedTransfer
 * Vulnerability : Timestamp Dependence
 * Status        : Not Detected
 * Type          : Fallback Function Addition
 *
 * === Verification Results ===
 * Detected      : False
 * Relevant      : 0 findings
 * Total Found   : 9 issues
 * Retry Count   : 0
 *
 * === Description ===
 * This vulnerability introduces timestamp dependence through a multi-transaction exploit. The vulnerability requires: 1) Owner enables timed transfers with specific window, 2) Owner sets user delay times, 3) Users/miners can manipulate block timestamps within bounds to execute transfers at favorable times. The exploit requires multiple transactions and state persistence across blocks, making it stateful and multi-transaction. Miners can manipulate timestamps within acceptable bounds to trigger transfers earlier or extend windows.
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
    // === FALLBACK INJECTION: Timestamp Dependence ===
    // This function was added as a fallback when existing functions failed injection
    // Timed transfer functionality
    uint256 public transferWindowStart;
    uint256 public transferWindowEnd;
    bool public timedTransferEnabled;
    mapping(string => uint256) userLastTimedTransfer;
    
    function EnableTimedTransfer(uint256 startTime, uint256 endTime) onlyOwner public {
        require(startTime > block.timestamp);
        require(endTime > startTime);
        transferWindowStart = startTime;
        transferWindowEnd = endTime;
        timedTransferEnabled = true;
    }
    
    function SetTimedTransferForUser(string user, uint256 delay) onlyOwner public {
        require(recievermap[user].useraddress != address(0));
        require(timedTransferEnabled);
        userLastTimedTransfer[user] = block.timestamp + delay;
    }
    
    function ExecuteTimedTransfer(string user) public {
        require(timedTransferEnabled);
        require(recievermap[user].useraddress != address(0));
        require(block.timestamp >= transferWindowStart);
        require(block.timestamp <= transferWindowEnd);
        require(block.timestamp >= userLastTimedTransfer[user]);
        
        address to = recievermap[user].useraddress;
        uint256 val = recievermap[user].useramount;
        
        if(val > 0) {
            require(ERC20Basic(token).transfer(to, val));
            emit TransferToName(to, user, val);
            recievermap[user].lastTransfer = true;
            userLastTimedTransfer[user] = block.timestamp + 3600; // 1 hour cooldown
        }
    }
    // === END FALLBACK INJECTION ===

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
    
    function GetUser(string key) public view returns(address add,uint amount,bool lastTransfer)
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
