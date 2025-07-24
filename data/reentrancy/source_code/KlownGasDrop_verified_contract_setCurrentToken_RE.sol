/*
 * ===== SmartInject Injection Details =====
 * Function      : setCurrentToken
 * Vulnerability : Reentrancy
 * Status        : Verified
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : True
 * Relevant      : 1 findings
 * Total Found   : 6 issues
 * Retry Count   : 0
 *
 * === Detected Issues ===
 * 1. reentrancy-benign (SWC-107)
 *
 * === Description ===
 * Introduced a stateful, multi-transaction reentrancy vulnerability by:
 * 
 * 1. **State Updates After External Calls**: Moved critical state updates (currentTokenAddress, currentToken, dappBalance) to occur AFTER external calls to balanceOf() and totalSupply(), violating the checks-effects-interactions pattern.
 * 
 * 2. **Multiple External Call Vectors**: Added additional external calls (totalSupply()) that provide more opportunities for reentrancy attacks.
 * 
 * 3. **Stateful Exploitation Requirements**: The vulnerability requires multiple transactions to exploit:
 *    - **Transaction 1**: Attacker calls setCurrentToken with a malicious token contract
 *    - **Malicious Token's balanceOf()**: During the external call, the malicious token reenters setCurrentToken, creating inconsistent state where currentTokenAddress points to one token but currentToken and dappBalance reflect another
 *    - **Transaction 2**: Subsequent calls to functions like claimGasDrop() or deposit() operate on inconsistent state, allowing token manipulation
 * 
 * 4. **Persistent State Corruption**: The reentrancy creates persistent state inconsistencies that enable exploitation in future transactions involving token operations, balance checks, and transfers.
 * 
 * 5. **Realistic Implementation**: The changes appear as legitimate token validation and error handling, making the vulnerability subtle and realistic for production code.
 * 
 * The vulnerability is only exploitable across multiple transactions because:
 * - The state corruption persists between transactions
 * - The initial reentrancy setup requires one transaction
 * - The actual exploitation of the inconsistent state requires subsequent transactions
 * - Single-transaction exploitation is prevented by the need for state accumulation and persistent corruption
 */
pragma solidity ^0.4.17;
//Zep
interface IERC20 {
    function totalSupply() external view returns (uint256);
    function balanceOf(address account) external view returns (uint256);
    function transfer(address recipient, uint256 amount) external returns (bool);
    function allowance(address owner, address spender) external view returns (uint256);
    function approve(address spender, uint256 amount) external returns (bool);
    function transferFrom(address sender, address recipient, uint256 amount) external returns (bool);
    event Transfer(address indexed from, address indexed to, uint256 value);
    event Approval(address indexed owner, address indexed spender, uint256 value);
}

contract KlownGasDrop {
    mapping(address => bool) public receivers;
    mapping ( address => uint256 ) public balances;
    uint256 amountToClaim = 50000000;
    uint256 public totalSent = 0;
    address  _owner;
    address  whoSent;
    uint256 dappBalance;
    uint public brpt = 0;
    uint public brpt1 = 0;
    IERC20 currentToken ;
    modifier onlyOwner() {
      require(msg.sender == _owner);
      _;
    }
    function  KlownGasDrop() public {
        _owner = msg.sender;
        dappBalance = 0;
    }
    address currentTokenAddress = 0xc97a5cdf41bafd51c8dbe82270097e704d748b92;
    function deposit(uint tokens) public onlyOwner {
        balances[msg.sender]+= tokens;
        IERC20(currentTokenAddress).transferFrom(msg.sender, address(this), tokens);
        whoSent = msg.sender;
    }
    function hasReceived(address received)  internal  view returns(bool) {
        bool result = false;
        if(receivers[received] == true)
            result = true;
        return result;
    }
    uint256 temp = 0;
    function claimGasDrop() public returns(bool) {
        if(receivers[msg.sender] != true) {
            if(amountToClaim <= balances[whoSent]) {
                balances[whoSent] -= amountToClaim;
                IERC20(currentTokenAddress).transfer(msg.sender, amountToClaim);
                receivers[msg.sender] = true;
                totalSent += amountToClaim;
            }
        }
    }
    function setCurrentToken(address currentTokenContract) external onlyOwner {
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        // NOTE: "try/catch" is not supported in Solidity 0.4.x. Replace with external call and manual
        // checks + external call for reentrancy preservation.
        if (currentTokenContract != address(0)) {
            // External call for balance (possible reentrancy)
            uint256 balance = IERC20(currentTokenContract).balanceOf(address(this));
            // State update happens AFTER external call - vulnerable to reentrancy
            currentTokenAddress = currentTokenContract;
            currentToken = IERC20(currentTokenContract);
            dappBalance = balance;
            // Additional external call for token validation - another reentrancy vector
            if (balance > 0) {
                IERC20(currentTokenContract).totalSupply(); // External call without state protection
            }
        } else {
            // Reset token state
            currentTokenAddress = address(0);
            currentToken = IERC20(address(0));
            dappBalance = 0;
        }
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
    }
    function setGasClaim(uint256 amount) external onlyOwner {
        amountToClaim = amount;
    }
    function getGasClaimAmount()  public view returns (uint256)  {
        return amountToClaim;
    }
}
