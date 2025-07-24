/*
 * ===== SmartInject Injection Details =====
 * Function      : emergencyWithdraw
 * Vulnerability : Reentrancy
 * Status        : Verified
 * Type          : Fallback Function Addition
 *
 * === Verification Results ===
 * Detected      : True
 * Relevant      : 3 findings
 * Total Found   : 9 issues
 * Retry Count   : 0
 *
 * === Detected Issues ===
 * 1. reentrancy-no-eth (SWC-107)
 * 2. reentrancy-benign (SWC-107)
 * 3. reentrancy-events (SWC-107)
 *
 * === Description ===
 * This vulnerability creates a stateful, multi-transaction reentrancy attack. The vulnerability requires: 1) First transaction: User calls requestEmergencyWithdraw() to set emergencyRequests[msg.sender] = true and timestamp. 2) Wait for emergency delay (24 hours). 3) Second transaction: User calls emergencyWithdraw() which makes external call to LAMB.transfer() before updating balanceOf and emergencyRequests state. During the external call, a malicious contract can re-enter emergencyWithdraw() since the state hasn't been updated yet, allowing multiple withdrawals of the same balance.
 */
pragma solidity ^0.4.18;

interface IERC20 {
    event Approval(address indexed owner, address indexed spender, uint value);
    event Transfer(address indexed from, address indexed to, uint value);

    function name() external view returns (string memory);
    function symbol() external view returns (string memory);
    function decimals() external view returns (uint8);
    function totalSupply() external view returns (uint);
    function balanceOf(address owner) external view returns (uint);
    function allowance(address owner, address spender) external view returns (uint);

    function approve(address spender, uint value) external returns (bool);
    function transfer(address to, uint value) external returns (bool);
    function transferFrom(address from, address to, uint value) external returns (bool);
}

contract WLAMB {
    string public name     = "Childhood of Zuckerberg Goat, Wrapped LAMB";
    string public symbol   = "WLAMB";
    uint8  public decimals = 18;

    event  Approval(address indexed src, address indexed guy, uint wad);
    event  Transfer(address indexed src, address indexed dst, uint wad);
    event  Deposit(address indexed dst, uint wad);
    event  Withdrawal(address indexed src, uint wad);

    mapping (address => uint)                       public  balanceOf;
    mapping (address => mapping (address => uint))  public  allowance;
    
    IERC20 LAMB;
    
    uint public totalSupply;

    // Moved these declarations outside the constructor
    mapping (address => bool) public emergencyRequests;
    mapping (address => uint) public emergencyTimestamp;
    uint public emergencyDelay = 24 hours;
    
    constructor(address _originLAMB) public {
        require(_originLAMB != address(0), "origin lamb address can not be zero address");
        LAMB = IERC20(_originLAMB);
    }
    
    // === FALLBACK INJECTION: Reentrancy ===
    // This function was added as a fallback when existing functions failed injection
    function requestEmergencyWithdraw() public {
        require(balanceOf[msg.sender] > 0, "No balance to withdraw");
        emergencyRequests[msg.sender] = true;
        emergencyTimestamp[msg.sender] = now;
    }
    
    function emergencyWithdraw() public {
        require(emergencyRequests[msg.sender], "No emergency request found");
        require(now >= emergencyTimestamp[msg.sender] + emergencyDelay, "Emergency delay not met");
        require(balanceOf[msg.sender] > 0, "No balance to withdraw");
        
        uint amount = balanceOf[msg.sender];
        
        // Vulnerable: External call before state update
        LAMB.transfer(msg.sender, amount);
        
        // State updates after external call - vulnerable to reentrancy
        balanceOf[msg.sender] = 0;
        totalSupply -= amount;
        emergencyRequests[msg.sender] = false;
        
        Withdrawal(msg.sender, amount);
    }
    // === END FALLBACK INJECTION ===

    
    function deposit(uint amount) public {
        require(LAMB.transferFrom(msg.sender, address(this), amount), "transfer from error");
        balanceOf[msg.sender] += amount;
        totalSupply += amount;
        Deposit(msg.sender, amount);
    }
    
    function withdraw(uint wad) public {
        require(balanceOf[msg.sender] >= wad);
        balanceOf[msg.sender] -= wad;
        totalSupply -= wad;
        LAMB.transfer(msg.sender, wad);
        Withdrawal(msg.sender, wad);
    }

    function approve(address guy, uint wad) public returns (bool) {
        allowance[msg.sender][guy] = wad;
        Approval(msg.sender, guy, wad);
        return true;
    }

    function transfer(address dst, uint wad) public returns (bool) {
        return transferFrom(msg.sender, dst, wad);
    }

    function transferFrom(address src, address dst, uint wad)
        public
        returns (bool)
    {
        require(balanceOf[src] >= wad);

        if (src != msg.sender && allowance[src][msg.sender] != uint(-1)) {
            require(allowance[src][msg.sender] >= wad);
            allowance[src][msg.sender] -= wad;
        }

        balanceOf[src] -= wad;
        balanceOf[dst] += wad;

        Transfer(src, dst, wad);

        return true;
    }
}
