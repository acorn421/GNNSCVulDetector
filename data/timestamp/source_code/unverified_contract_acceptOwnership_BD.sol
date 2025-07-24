/*
 * ===== SmartInject Injection Details =====
 * Function      : acceptOwnership
 * Vulnerability : Timestamp Dependence
 * Status        : Not Detected
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : False
 * Relevant      : 0 findings
 * Total Found   : 1 issues
 * Retry Count   : 0
 *
 * === Description ===
 * This vulnerability introduces timestamp dependence in the ownership transfer process by adding time-based restrictions. The vulnerability requires multiple transactions to exploit: first the transferOwnership() function must be called to set the newOwner and record the request timestamp, then after waiting for the timelock period, acceptOwnership() can be called. The vulnerability allows miners to manipulate block.timestamp to bypass security delays or cause legitimate ownership transfers to expire, creating a multi-transaction attack vector where the state persists between transactions and timing manipulation can affect ownership control.
 */
pragma solidity ^0.4.16;

contract SuperEOS {
    string public name = "SuperEOS";      
    string public symbol = "SPEOS";              
    uint8 public decimals = 6;                
    uint256 public totalSupply;                

    bool public lockAll = false;               

    event Transfer(address indexed from, address indexed to, uint256 value);
    event FrozenFunds(address target, bool frozen);
    event OwnerUpdate(address _prevOwner, address _newOwner);
    address public owner;
    address internal newOwner = 0x0;
    mapping (address => bool) public frozens;
    mapping (address => uint256) public balanceOf;

    //---------init----------
    function SuperEOS() public {
        totalSupply = 2000000000 * 10 ** uint256(decimals);  
        balanceOf[msg.sender] = totalSupply;                
        owner = msg.sender;
    }
    //--------control--------
    modifier onlyOwner {
        require(msg.sender == owner);
        _;
    }
    function transferOwnership(address tOwner) onlyOwner public {
        require(owner!=tOwner);
        newOwner = tOwner;
    }
    // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY START =====
mapping(address => uint256) public ownershipRequestTime;
    uint256 public ownershipTimelock = 24 hours;
    uint256 public ownershipDeadline = 7 days;
    
    function acceptOwnership() public {
        require(msg.sender==newOwner && newOwner != 0x0);
        
        // Get the timestamp when ownership was requested
        uint256 requestTime = ownershipRequestTime[msg.sender];
        require(requestTime > 0, "No ownership request found");
        
        // Enforce time lock - must wait at least 24 hours
        require(block.timestamp >= requestTime + ownershipTimelock, "Ownership timelock not expired");
        
        // Enforce deadline - must accept within 7 days
        require(block.timestamp <= requestTime + ownershipDeadline, "Ownership request expired");
        
// ===== SMARTINJECT: Timestamp Dependence VULNERABILITY END =====
        owner = newOwner;
        newOwner = 0x0;
        // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY START =====
        delete ownershipRequestTime[msg.sender];
        // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY END =====
        emit OwnerUpdate(owner, newOwner);
    }

    function freezeAccount(address target, bool freeze) onlyOwner public {
        frozens[target] = freeze;
        emit FrozenFunds(target, freeze);
    }

    function freezeAll(bool lock) onlyOwner public {
        lockAll = lock;
    }

    //-------transfer-------
    function transfer(address _to, uint256 _value) public {
        _transfer(msg.sender, _to, _value);
    }
    function _transfer(address _from, address _to, uint _value) internal {
        require(!lockAll);
        require(_to != 0x0);
        require(balanceOf[_from] >= _value);
        require(balanceOf[_to] + _value >= balanceOf[_to]);
        require(!frozens[_from]); 

        uint previousBalances = balanceOf[_from] + balanceOf[_to];
        balanceOf[_from] -= _value;
        balanceOf[_to] += _value;
        emit Transfer(_from, _to, _value);
        assert(balanceOf[_from] + balanceOf[_to] == previousBalances);
    }
}