import org.spockframework.runtime.model.parallel.ExecutionMode
import spock.config.ParallelConfiguration

runner {
    filterStackTrace false
    optimizeRunOrder true
    parallel {
        enabled true
        defaultSpecificationExecutionMode = ExecutionMode.CONCURRENT
        defaultExecutionMode = ExecutionMode.SAME_THREAD
        dynamic(2.0)
    }
}