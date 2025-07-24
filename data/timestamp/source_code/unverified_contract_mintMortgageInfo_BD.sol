/*
 * ===== SmartInject Injection Details =====
 * Function      : mintMortgageInfo
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
 * Introduced a stateful, multi-transaction Timestamp Dependence vulnerability through time-based business logic validation and bonus calculation system. The vulnerability requires multiple transactions to exploit:
 * 
 * **Transaction 1 (State Setup):** 
 * - Attacker creates a mortgage project during off-hours when the function should reject creation
 * - By manipulating block.timestamp, they can bypass the business hours validation
 * - The creationTime is stored in state, creating persistent vulnerability conditions
 * 
 * **Transaction 2+ (Exploitation):**
 * - Attacker can exploit the 24-hour re-creation window by manipulating timestamps
 * - They can repeatedly recreate the same project with different bonus multipliers
 * - By controlling block.timestamp across multiple transactions, they can:
 *   - Bypass the business hours restriction
 *   - Maximize bonus multipliers by appearing to create mortgages in "early morning"
 *   - Reset the 24-hour cooldown period artificially
 * 
 * **Multi-Transaction Nature:**
 * - Transaction 1 establishes vulnerable state (creationTime stored)
 * - Transaction 2 exploits the time-dependent re-creation logic
 * - Additional transactions can continue exploiting the bonus system
 * - The vulnerability accumulates value over multiple state changes
 * 
 * **Realistic Exploitation Scenarios:**
 * - Miners can manipulate block.timestamp within ~15 minute windows
 * - Attackers can chain transactions with incremental timestamp manipulation
 * - The 24-hour window creates a prolonged exploitation opportunity
 * - Business hours validation can be completely bypassed with timestamp control
 * 
 * The vulnerability is realistic as it mimics real-world mortgage systems with time-sensitive operations, but the reliance on block.timestamp for critical business logic creates exploitable conditions that require multiple transactions to fully realize.
 */
pragma solidity ^0.4.22;
contract Ownable {
  address public owner;

  event OwnershipRenounced(address indexed previousOwner);
  event OwnershipTransferred(
    address indexed previousOwner,
    address indexed newOwner
  );

  /**
   * @dev 可拥有的构造函数将合同的原始“所有者”设置为发送者
   * account.
   */
  constructor() public {
    owner = msg.sender;
  }

  /**
   * @dev 如果由所有者以外的任何帐户调用，则抛出
   */
  modifier onlyOwner() {
    require(msg.sender == owner);
    _;
  }

  /**
   * @dev 允许业主放弃合同的控制权.
   */
  function renounceOwnership() public onlyOwner {
    emit OwnershipRenounced(owner);
    owner = address(0);
  }

  /**
   * @dev 允许当前所有者将合同的控制转移给新所有者.
   */
  function transferOwnership(address _newOwner) public onlyOwner {
    _transferOwnership(_newOwner);
  }

  /**
   * @dev 将合同的控制权移交给新所有者.
   */
  function _transferOwnership(address _newOwner) internal {
    require(_newOwner != address(0));
    emit OwnershipTransferred(owner, _newOwner);
    owner = _newOwner;
  }
}

contract TokenMall is Ownable {
  /**
   * @dev 抵押物上链信息.
   */
  struct MortgageInfo {
      bytes32 projectId;//项目ID 
      string currency;//抵押币种 
      string mortgageAmount;//抵押数量 
      string releaseAmount;//释放数量 
      uint256 creationTime; // creation timestamp
      uint256 bonusMultiplier; // bonus
  }
  mapping(bytes32 =>MortgageInfo) mInfo;
  bytes32[] mortgageInfos;
   
  /**
   * @dev 添加数据.
   */
    event MessageMintInfo(address sender,bool isScuccess,string message);
    event MessageUpdateInfo(address sender,bool isScuccess,string message);
    function mintMortgageInfo(string _projectId,string currency,string mortgageAmount,string releaseAmount) onlyOwner public {
        bytes32 proId = stringToBytes32(_projectId);
        if(mInfo[proId].projectId != proId){
              // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY START =====
              // Time-based validation for mortgage creation window
              uint256 currentTime = block.timestamp;
              uint256 dailyWindow = currentTime % 86400; // 24 hours in seconds
              
              // Only allow mortgage creation during "business hours" (8 AM to 6 PM UTC)
              require(dailyWindow >= 28800 && dailyWindow <= 64800, "Mortgage creation only allowed during business hours");
              
              // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY END =====
              mInfo[proId].projectId = proId;
              mInfo[proId].currency = currency;
              mInfo[proId].mortgageAmount = mortgageAmount;
              mInfo[proId].releaseAmount = releaseAmount;
              // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY START =====
              // Store creation timestamp for future operations
              mInfo[proId].creationTime = currentTime;
              // Time-dependent bonus calculation - early morning gets better rates
              if(dailyWindow < 36000) { // Before 10 AM UTC
                  mInfo[proId].bonusMultiplier = 110; // 10% bonus
              } else if(dailyWindow < 43200) { // Before 12 PM UTC
                  mInfo[proId].bonusMultiplier = 105; // 5% bonus
              } else {
                  mInfo[proId].bonusMultiplier = 100; // No bonus
              }
              // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY END =====
              mortgageInfos.push(proId);
              emit MessageMintInfo(msg.sender, true,"添加成功");
            return;
        }else{
             // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY START =====
             // Allow project re-creation if enough time has passed (24 hours)
             if(block.timestamp - mInfo[proId].creationTime > 86400) {
                 mInfo[proId].currency = currency;
                 mInfo[proId].mortgageAmount = mortgageAmount;
                 mInfo[proId].releaseAmount = releaseAmount;
                 mInfo[proId].creationTime = block.timestamp;
                 // Recalculate bonus based on current time
                 uint256 _currentTime = block.timestamp;
                 uint256 _dailyWindow = _currentTime % 86400;
                 if(_dailyWindow < 36000) {
                     mInfo[proId].bonusMultiplier = 110;
                 } else if(_dailyWindow < 43200) {
                     mInfo[proId].bonusMultiplier = 105;
                 } else {
                     mInfo[proId].bonusMultiplier = 100;
                 }
                 emit MessageMintInfo(msg.sender, true,"项目更新成功");
                 return;
             }
             // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY END =====
             emit MessageMintInfo(msg.sender, false,"项目ID已经存在");
            return;
        }
    }
    
    function updateMortgageInfo(string _projectId, string releaseAmount) onlyOwner public {
        bytes32 proId = stringToBytes32(_projectId);
        if(mInfo[proId].projectId == proId){
            mInfo[proId].releaseAmount = releaseAmount;
            mortgageInfos.push(proId);
            emit MessageUpdateInfo(msg.sender, true,"修改成功");
            return;
        }else{
            emit MessageUpdateInfo(msg.sender, false,"项目ID不存在");
            return;
        }
    }
 
    /**
     * @dev 查询数据.
     */
    function getMortgageInfo(string _projectId) 
        public view returns(string projectId,string currency,string mortgageAmount,string releaseAmount){
         bytes32 proId = stringToBytes32(_projectId);
         MortgageInfo memory mi = mInfo[proId];
        return (_projectId,mi.currency,mi.mortgageAmount,mi.releaseAmount);
    }

    /// string类型转化为bytes32型转
    function stringToBytes32(string memory source) internal constant returns(bytes32 result){
        assembly{
            result := mload(add(source,32))
        }
    }
    /// bytes32类型转化为string型转
    function bytes32ToString(bytes32 x) internal constant returns(string){
        bytes memory bytesString = new bytes(32);
        uint charCount = 0 ;
        for(uint j = 0 ; j<32;j++){
            byte char = byte(uint(x) / (2 ** (8*(31-j))));
            if(char !=0){
                bytesString[charCount] = char;
                charCount++;
            }
        }
        bytes memory bytesStringTrimmed = new bytes(charCount);
        for(j=0;j<charCount;j++){
            bytesStringTrimmed[j]=bytesString[j];
        }
        return string(bytesStringTrimmed);
    }

}
