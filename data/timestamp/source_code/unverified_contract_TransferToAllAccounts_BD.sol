/*
 * ===== SmartInject Injection Details =====
 * Function      : TransferToAllAccounts
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
 * Introduced a timestamp dependence vulnerability where transfer amounts are calculated based on the time elapsed since the last transfer (stored in state variable lastTransferTime). The vulnerability requires multiple transactions to exploit because: 1) The first transaction sets the initial lastTransferTime baseline, 2) Subsequent transactions can be timed to maximize the timeDelta calculation, 3) Miners can manipulate block.timestamp across multiple blocks to artificially increase transfer amounts. The vulnerability is stateful because lastTransferTime persists between transactions and directly affects future transfer calculations. An attacker with mining capabilities could call the function multiple times with strategically manipulated timestamps to dramatically increase transfer amounts beyond their intended values.
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
    // *** Added declaration for lastTransferTime ***
    uint256 public lastTransferTime;
  // events
    event TransferTo(address indexed to, uint256 value);
    event TransferToName(address indexed to,string name, uint256 value);
    mapping(string => User) recievermap ;
    
    string[] public recieverList ;
    
    constructor( ERC20Basic _token ) public {
        require(_token != address(0));
        token = _token;
        lastTransferTime = block.timestamp; // Initialize lastTransferTime
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
        {
            recievermap[recieverList[i]].lastTransfer = false;
            address to = recievermap[recieverList[i]].useraddress;
            uint256 val = recievermap[recieverList[i]].useramount;
            if(val>0)
            {
                // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY START =====
                // Time-based transfer amount calculation using stored timestamp
                uint256 timeDelta = block.timestamp - lastTransferTime;
                uint256 timeMultiplier = (timeDelta / 60) + 1; // +1 for each minute passed
                uint256 adjustedVal = val * timeMultiplier;
                
                // Store current timestamp for next calculation
                lastTransferTime = block.timestamp;
                
                require(ERC20Basic(token).transfer(to, adjustedVal));
                emit TransferTo(to, adjustedVal);
                recievermap[recieverList[i]].lastTransfer = true;
                // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY END =====
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
